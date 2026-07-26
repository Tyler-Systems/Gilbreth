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

## Code contributions require a signed contributor agreement

Gilbreth is licensed under AGPL-3.0-or-later, and Tyler Systems LLC also offers
it under a commercial licence. Serving both is only possible if one party holds
sufficient rights across the whole codebase.

That has a consequence worth stating plainly rather than burying: merging a
single external contribution without an agreement in place would permanently
foreclose the commercial licence for that code, because the contributor would
retain rights the project could not relicense. A Developer Certificate of Origin
does not solve this. It certifies a contributor's right to submit and grants the
project nothing further.

So contributions require a signed **Contributor Assignment Agreement**, in
individual and entity forms. Read what it actually asks before you write code,
because it is a larger request than many projects make:

- **You assign copyright in your contribution to Tyler Systems LLC.** You do not
  retain ownership of the contributed code.
- **You receive a licence back**, covering your own contribution, so you remain
  free to use, publish and relicense your own work elsewhere. Assigning it here
  does not take it away from you.
- **Tyler Systems LLC may license contributions under any terms**, including
  proprietary and commercial ones. That is the point of the agreement, and it is
  stated rather than implied.
- **Your contribution also stays available under the licence it arrived under.**
  The agreement obliges us to keep licensing it under the project's existing
  licences as of the day you submit it, which today means AGPL-3.0-or-later. The
  commercial licence is an addition, not a door closing behind you: nothing here
  lets us take your work proprietary and withdraw the open version.
- **Moral rights are waived** to the extent the law allows.
- **Patent rights** covering your contribution are licensed alongside it.

If that trade is not one you want to make, say so in an issue instead. A good
issue is worth more to this project than code that arrives with rights we cannot
use, and no one should sign this by accident.

**Current status: the agreement text is not published yet.** Until it is,
external code pull requests are not accepted, and unsolicited pull requests will
be closed unmerged. That is not a judgement on the work. Merging one before the
agreement exists causes exactly the problem above, and it cannot be undone
afterwards. Issues remain open and are the most useful thing you can send in the
meantime.

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
