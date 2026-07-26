# Contributing to Gilbreth

Issues are welcome now. **Code contributions are not being accepted yet** —
see the status below.

## Reporting

Bug reports and feature proposals go to
[GitHub Issues](https://github.com/Tyler-Systems/Gilbreth/issues). For anything
with a security or privacy dimension, follow [SECURITY.md](SECURITY.md) instead
of opening a public issue.

Useful bug reports say what you did, what happened, what you expected, and
which platform and version. Gilbreth sends no telemetry, so a report is the only
way a problem reaches us.

## Code contributions require a signed CLA

Gilbreth is licensed under AGPL-3.0-or-later, and Tyler Systems LLC also offers
it under a commercial licence. Serving both is only possible if one party holds
sufficient rights across the whole codebase.

That has a consequence worth stating plainly rather than burying: merging a
single external contribution without an agreement in place would permanently
foreclose the commercial licence for that code, because the contributor would
retain rights the project could not relicense. A Developer Certificate of Origin
does not solve this — it certifies a contributor's right to submit, but grants
the project nothing further.

So contributions require a **Contributor Licence Agreement**, in individual and
entity forms, granting Tyler Systems LLC the rights needed to distribute
contributed work under both licences. Contributors keep the copyright in what
they write.

**Current status: the CLA is not published yet.** Until it is, external code
pull requests are not accepted, and unsolicited pull requests will be closed
unmerged — not as a judgement on the work, but because merging one before the
agreement exists causes exactly the problem above. Issues remain open and are
the most useful thing you can send in the meantime.

## Building and testing

See [docs/MAINTAINING.md](docs/MAINTAINING.md) for the toolchain, the commands,
and the change discipline this codebase expects, including the enforced
product-copy rules.

## What Gilbreth will not accept

Some contributions will be declined regardless of quality, because they
contradict the product's contract:

- anything that sends captured data off the machine, or adds telemetry;
- capture of typed key content by default;
- detection-evasion behaviour, for antivirus/EDR or anything else;
- automation that acts on the user's behalf — Gilbreth observes and reports,
  it does not drive other software.

If you are unsure whether an idea fits, open an issue before writing code.
