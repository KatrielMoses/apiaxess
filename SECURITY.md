# Security Policy

APIaxess is a security-testing tool, so we take vulnerabilities in APIaxess itself
seriously and appreciate reports made in good faith.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately, either way:

- Email **security@apiaxess.dev** with details and, ideally, a proof of concept.
- Or use GitHub's **private vulnerability reporting** on this repository
  (Security → Report a vulnerability).

Please include: affected version/commit, platform, reproduction steps, and the
impact you observed. If you can, suggest a fix.

## What to expect

- We aim to acknowledge a report within a few business days.
- We'll keep you updated on our assessment and a fix timeline, and credit you in
  the release notes if you'd like (or stay anonymous — your call).
- Please give us reasonable time to ship a fix before any public disclosure.

## Scope

In scope: the APIaxess engine, GUI, packaging/installers, and the update/download
paths. Bundled third-party tools (Chromium, OpenJDK, ffuf, Frida, apktool, jadx,
QEMU/Android images) should be reported to their respective upstream projects,
though we're happy to help route a report or bump a pinned version.

## Responsible use

APIaxess is built for **authorized** security testing of systems you own or have
explicit permission to test. Scope in APIaxess is advisory and honest — it records
and warns, it does not authorize you. You are responsible for having authorization
before you test a target.
