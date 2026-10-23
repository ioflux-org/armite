# Security policy

Armite is a local emulator: it mints tokens and evaluates authorization
on your own machine, with a private CA it generates and built-in
credentials that are public by design. A bug in token minting,
signature verification or the RBAC evaluation still matters, because
people rely on Armite to tell them what Azure would do.

## Supported versions

The latest release on the [releases page](https://github.com/ioflux-org/armite/releases)
receives fixes. Older releases do not.

## Reporting a vulnerability

Use GitHub's private reporting: **Security → Report a vulnerability**
on this repository. It opens a private advisory that only the
maintainers can see. Please do not open a public issue for a security
problem.

Include the version (`armite version`), the platform, what you did,
what happened and what you expected. A proof of concept against a
local Armite is welcome; one against anyone else's systems is not.

You will get an acknowledgement within a week. Fixes ship as a patch
release with credit to the reporter, unless you prefer otherwise.

## Scope today

Armite v0.1 is built for one developer's machine: the documented
commands bind to 127.0.0.1, and the built-in principal's secret is
public. Reports that assume Armite is reachable from a network are
out of scope for now — not because the idea is wrong, but because a
shared deployment needs things v0.1 does not have: operator-defined
principals only, the built-in ones switched off, and an explicit
opt-in to listen on other interfaces. That is on the roadmap; until it
ships, treat a network-exposed Armite as an open door.

Also out of scope:

- Anything that requires the built-in credentials (`armite-secret`,
  the fixed client and object ids): they are documented and public.
- The private CA being trusted by a client the user configured to
  trust it.
