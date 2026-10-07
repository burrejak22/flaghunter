# Security Policy

## Security maintainer

Jake Burre (@burrejak22) is the security maintainer for flaghunter.

## Reporting a vulnerability

Do not open a public issue. Email the maintainer via the address listed on
the GitHub profile, or open a private security advisory on the repo:

https://github.com/burrejak22/flaghunter/security/advisories/new

Please include:

- what the issue is and where it lives in the code
- steps to reproduce, or a proof of concept
- what you think the impact is

You will get a response within 7 days. If the report is confirmed, a fix
will be released and you will be credited unless you ask not to be.

## Scope

This policy covers the flaghunter package published to PyPI and the code in
this repository. flaghunter depends on cryptsmith for its crypto and pcap
primitives; vulnerabilities in those shared primitives should be reported to
cryptsmith (https://github.com/burrejak22/cryptsmith/security/advisories/new).
