# Security Policy

## Supported Versions

We only support the most recent release.

| Version | Supported          |
| ------- | ------------------ |
| 0.11.0  | :white_check_mark: |
| 0.10.0  | :x:                |
| 0.9.0   | :x:                |
| 0.8.0   | :x:                |
| 0.7.0   | :x:                |
| 0.6.1   | :x:                |
| 0.6.0   | :x:                |
| 0.5.3   | :x:                |
| 0.5.2   | :x:                |
| 0.5.1   | :x:                |
| < 0.5   | :x:                |

## Background

A vulnerability to this software can take many forms: Incorrect logic, missing safety checks, bad API
use, either "downwards" (towards `liboqs`) or "upwards" (towards `openssl`), missing memory boundary
checks, etc.

For any such problem, reporters are first asked to consider whether these are indeed so serious that
they indeed require issuance of a [CVE](https://www.cve.org). In most cases, this is not necessary,
particularly considering this project is not meant for productive use, i.e., that there should be no
software in need of a patch under CVE "embargo". Therefore, to ease the load on the maintenance team,
we ask to report simple vulnerabilities by creation of issues or even better, directly by providing a
PR with a fix. This helps the community best by immediately fixing the problem when detected and
reduces the strain on a very thin and also time-limited base of maintainers.

What cannot be seen as a vulnerability to this software at all is incorrect or weak PQ algorithm
implementations actually provided by either of these libraries (`liboqs` or `libcrypto` from
`openssl`). Any such problem shall be reported to those projects, respectively. Any report of
this sort opened in this repository will be closed immediately without further action.

## Reporting a serious Vulnerability

Considering the background above, if you still think you have found a serious vulnerability, please
follow [this information to report it](https://openquantumsafe.org/liboqs/security.html#reporting-security-bugs)
and/or directly create [a draft security advisory via github](https://github.com/open-quantum-safe/oqs-provider/security/advisories/new).

Should too many CVE reports be received that do not warrant this designation, and/or reports are
generated with the sole goal of receiving ["CVE reporting credits", or are plain AI slop](https://daniel.haxx.se/blog/2025/07/14/death-by-a-thousand-slops/),
this project reserves the right to completely stop accepting CVE reports by way of disabling the
Security Advisory interface.
