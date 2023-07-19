---
name: Bug report
about: Create a report to help us improve
title: ''
labels: ''
assignees: ''

---

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected behavior**
A clear and concise description of what you expected to happen.

**Screenshots**
If applicable, add screenshots to help explain your problem.

**Environment (please complete the following information):**
 - OS: [e.g. Ubuntu 20]
 - OpenSSL version [e.g., 3.2.0-dev]
 - Version [e.g. 0.4.0]

Please run the following commands to obtain the version information:
 - For OpenSSL: `openssl version` 
 - For oqsprovider: `openssl list -providers`

**Additional context**
Add any other context about the problem here.

**Hints**
To exclude a build/setup error, please consider running your test
commands to reproduce the problem in our [pre-build docker image](https://hub.docker.com/repository/docker/openquantumsafe/oqs-ossl3/general),
e.g. as such: `docker run -it openquantumsafe/oqs-ossl3` and
provide full command input and output traces in the bug report.

