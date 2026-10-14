# Third-party software

NullBound launches third-party scanners but does not vendor their source or
binaries. The optional setup scripts download tools into the ignored
`.nullbound-tools` directory only when an operator requests installation. Do not
include that directory in a NullBound source archive, release artifact, container,
or redistributed VM image without reviewing every upstream license and version.

| Component | Upstream | NullBound treatment |
| --- | --- | --- |
| Subfinder | <https://github.com/projectdiscovery/subfinder> | Downloaded from upstream or built with Go |
| dnsx | <https://github.com/projectdiscovery/dnsx> | Downloaded from upstream or built with Go |
| httpx | <https://github.com/projectdiscovery/httpx> | Downloaded from upstream or built with Go |
| gau | <https://github.com/lc/gau> | Downloaded from upstream or built with Go |
| ffuf | <https://github.com/ffuf/ffuf> | Downloaded from upstream or built with Go |
| tlsx | <https://github.com/projectdiscovery/tlsx> | Downloaded from upstream or built with Go |
| Nuclei | <https://github.com/projectdiscovery/nuclei> | Downloaded from upstream or built with Go; templates have their own provenance |
| sqlmap | <https://github.com/sqlmapproject/sqlmap> | Cloned into the local tool directory |
| Nmap | <https://nmap.org/> | Installed from the operating system or official installer; never bundled |
| Npcap | <https://npcap.com/> | Optional Windows prerequisite installed separately under its own terms |

Python application dependencies are installed from `requirements.txt` into the
operator's environment and remain governed by their upstream licenses. SecLists
wordlists are discovered from an existing system installation or supplied by the
operator; NullBound does not copy SecLists into the repository.

NullBound's setup scripts are installation conveniences, not permission to
redistribute another project's software. Upstream licenses and release terms are
authoritative and must be checked again when producing a release that embeds any
third-party component.
