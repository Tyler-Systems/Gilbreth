# Contributing to Gilbreth

Issues and code contributions are both welcome. Code requires a signed
[Contributor Licence Agreement](CONTRIBUTOR_AGREEMENT.md); a bot will ask you to
accept it on your first pull request.

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
does not solve this. It certifies a contributor's right to submit and grants the
project nothing further.

So contributions require a signed **Contributor Licence Agreement**, in
individual and entity forms. Here is what it actually does, so you can decide
before writing code rather than after:

- **You keep the copyright in what you write.** The agreement says so in its
  first clause, and adds that you keep every right to use or license your own
  contribution that you would have had without signing it.
- **You license that work to Tyler Systems LLC** broadly enough to sublicense:
  perpetual, worldwide, non-exclusive, royalty-free and irrevocable.
- **Tyler Systems LLC may license contributions under any terms**, including
  commercial and proprietary ones. That is the point of the agreement and it is
  stated rather than implied.
- **Your contribution stays available under the licence it arrived under.** We
  are obliged to also keep licensing it under the licences the project was using
  the day you submitted, which today means AGPL-3.0-or-later. The commercial
  licence is an addition, not a door closing behind you.
- **That obligation has teeth.** The licence you grant is expressly conditioned
  on our compliance with it. If we ever stopped honouring the open licence, the
  grant that lets us ship your code would fail with it.
- **Patent rights** covering your contribution are licensed alongside it.

If that trade is not one you want to make, open an issue instead. A good issue
is worth more here than code that arrives with rights the project cannot use,
and nobody should sign this by accident.

The agreement is published at
[CONTRIBUTOR_AGREEMENT.md](CONTRIBUTOR_AGREEMENT.md). Read it before writing
code rather than after.

**How it works in practice.** Open a pull request as normal. A bot comments with
a link to the exact version of the agreement being offered, and asks you to reply
accepting it. Once you have, the check goes green and the pull request can be
reviewed on its merits. You accept once, not per pull request.

If the agreement is not a trade you want to make, an issue is a genuinely useful
contribution and needs no agreement at all.

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
