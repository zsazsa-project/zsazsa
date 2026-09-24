# Security policy

## Reporting a vulnerability

Report it privately through
[GitHub's advisory form](https://github.com/zsazsa-project/zsazsa/security/advisories/new),
or by email to koen.vanimpe@cudeso.be if you would rather not use GitHub.
Please do not open a public issue for something that is exploitable.

Tell us what you found, how to reproduce it, and what it gets an attacker.


## Transparency

We think being
open about vulnerabilities matters, however minor they turn out to be. We would
rather publish an advisory for something almost nobody was at risk from than
fix it quietly and say nothing.

Every report we accept gets a GitHub security advisory, and a CVE where one is
warranted, crediting you unless you ask us not to. If we decide something is not
a vulnerability, we will tell you why rather than let the report go quiet.

## Scope

zsazsa is self-hosted and runs on top of MISP. A problem in MISP itself belongs
with [the MISP project](https://github.com/MISP/MISP/security/policy) rather
than here, and the same goes for PyMISP and the other dependencies.

Two things are current design rather than defects, so they are out of scope
unless you have found a way around them. zsazsa has no role-based authorisation
of its own: anyone who can reach it with a valid MISP session can use it, and
only approving and publishing are gated, on MISP's own `perm_publish`. It is
also meant to be served behind the same host as MISP, on an internal network,
and not exposed to the internet.
