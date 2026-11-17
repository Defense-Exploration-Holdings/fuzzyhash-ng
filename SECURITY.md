# Security policy

## Supported versions

Security fixes are released for the latest `1.x` version once 1.0 is out. Before that, only the latest pre-release is supported.

## Reporting a vulnerability

Please report vulnerabilities privately, not in a public issue. Use [Report a vulnerability](https://github.com/Defense-Exploration-Holdings/fuzzyhash-ng/security/advisories/new) on the Security tab of this repository, which opens a private advisory visible only to the maintainers. If you cannot use GitHub, e-mail security@defense-exploration.com.

Include the affected version, the input or digest strings that trigger the problem, and what you expected instead. In scope:

- a crash, hang, trap or out-of-bounds read or write on any input, including malformed digest strings;
- unbounded time or memory on any input (parsing is linear in the input and comparison is bounded);
- a WebAssembly module that leaves memory in a state the next call trusts.

Expect an acknowledgement within a few days. Once a fix is released, the advisory is published and you are credited if you wish.

## What is not a vulnerability

ssdeep and TLSH are similarity digests, not cryptographic hashes. Anyone can craft inputs that collide, or that look unrelated while being nearly identical. That is a property of the algorithms, documented by their authors, and not a bug in this implementation. Use fuzzy hashes for triage and clustering, never as an allow-list or for integrity checks.

A digest or score that differs from ssdeep 2.14.1 or TLSH 5.0.2 is a correctness bug. Report it as a normal issue.
