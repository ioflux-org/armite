# Contributing to Provisio

Thank you for considering a contribution. Provisio is small enough that
one person can hold the whole design in their head, and it is meant to
stay that way: every change should be understandable by reading the
code and the tests, without a conversation.

## What we are looking for

- Bug reports with the client that produced them: the `az --debug`
  excerpt, the SDK call, or the Terraform resource. The request that
  failed is the specification.
- Fidelity fixes: places where Provisio answers differently from Azure
  in a way a real client notices. Say which client noticed.
- New services, discussed in an issue first. A provider is a package
  under `internal/provider` registered in `cmd/provisio/main.go`; the
  Key Vault provider is the template.

## Ground rules

- **Standard library only.** The one permitted dependency is
  `gopkg.in/yaml.v3`. A PR that adds a dependency needs a reason no
  standard package can serve.
- **Tests with every change.** `gofmt -l`, `go vet ./...` and
  `go test -race ./...` must be clean. Handlers are tested through
  `httptest`; wire shapes are checked against the vendored Azure
  specifications in `internal/spectest`.
- **Cite the specification.** A struct that mirrors an Azure API model
  carries a `// Spec:` comment naming the file and definition.
- **Record divergences.** Anything that deliberately differs from Azure
  goes into `docs/divergences.md`, tagged, in the same PR.
- **No secrets, no real tenants.** Tests and examples use the built-in
  identities documented in the README.

## Workflow

1. Open an issue for anything larger than a fix, so the design is
   agreed before the code exists.
2. Branch from `main`, keep the change focused, and sign off every
   commit (`git commit -s`).
3. State in the pull request that you accept the Contributor License
   Agreement below (once per contributor, on your first PR).
4. Expect review comments to ask "why" as often as "what"; answer in the
   code comments where the next reader will look.
5. CI (`.github/workflows/ci.yml`) runs the gate - `gofmt`, `go vet`,
   `go test -race` - then a built server driven by az, the Azure SDK for
   JavaScript and Terraform, and the Docker image. Run the same before
   pushing with `./scripts/ci/all.sh` (needs go, az, node, terraform
   and `azurite-blob` on PATH, port 8443 free, and the hostnames of
   `./scripts/ci/hosts.sh` resolving); about six minutes, most of it
   the Terraform provider's pollers.

## Developer Certificate of Origin

Every commit must carry a `Signed-off-by` line with your real name and
e-mail address (`git commit -s` adds it). By signing off you certify the
[Developer Certificate of Origin 1.1](https://developercertificate.org/):
that you wrote the change or have the right to submit it under the
project's license, and that you understand the contribution is public
and kept indefinitely.

## Contributor License Agreement

The DCO says you may submit your change under the Apache License 2.0.
This agreement additionally gives the project the rights it needs to
keep the software usable if its licensing has to change, for example to
offer a commercial edition. Please read it; it is short.

**1. Definitions.** "You" means the individual accepting this agreement.
"Contribution" means any original work of authorship, including
modifications to existing work, that You intentionally submit to the
Project in any form, excluding anything conspicuously marked "Not a
Contribution". "Project" means Provisio and its documentation. "Maintainer"
means Agnivesh Chaubey, the maintainer of the Project, and any successor
organisation that takes over ownership of the Project, which will be
announced in this file.

**2. Grant of copyright license.** You grant to the Maintainer and to
recipients of software distributed by the Maintainer a perpetual,
worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright
license to reproduce, prepare derivative works of, publicly display,
publicly perform, sublicense and distribute Your Contributions and such
derivative works, under the Apache License 2.0 or under any other license
terms the Maintainer chooses, including licenses that are not open source.

**3. Grant of patent license.** You grant to the Maintainer and to
recipients of software distributed by the Maintainer a perpetual,
worldwide, non-exclusive, no-charge, royalty-free, irrevocable (except as
stated here) patent license to make, have made, use, offer to sell, sell,
import and otherwise transfer the Work, where such license applies only
to those patent claims licensable by You that are necessarily infringed
by Your Contribution alone or by combination of Your Contribution with
the Work to which it was submitted. If any entity institutes patent
litigation against You or any other entity alleging that Your
Contribution, or the Work to which You contributed, constitutes direct
or contributory patent infringement, any patent licenses granted to that
entity under this agreement for that Contribution or Work terminate as
of the date the litigation is filed.

**4. Your representations.** You represent that You are legally entitled
to grant the above licenses. If Your employer has rights to intellectual
property You create, You represent that You have received permission to
make Contributions on behalf of that employer, that the employer has
waived such rights for Your Contributions, or that the employer has
executed a separate corporate agreement with the Maintainer. You
represent that each Contribution is Your original creation, and that You
will identify any part of it that is not, together with its license and
any restrictions, in the pull request.

**5. No obligation of support.** You are not expected to provide support
for Your Contributions, except to the extent You wish to. Unless
required by law or agreed in writing, You provide Your Contributions on
an "AS IS" basis, without warranties or conditions of any kind.

**6. Changes.** You agree to notify the Maintainer of any facts or
circumstances of which You become aware that would make these
representations inaccurate.

**7. Acceptance.** You accept this agreement by including the sentence
"I have read and agree to the Contributor License Agreement in
CONTRIBUTING.md" in the description of your first pull request. Your
`Signed-off-by` lines identify You. The Maintainer keeps the pull request
as the record of acceptance.

**Corporate contributions.** If you contribute on behalf of an employer
or as part of a company's work, the company needs to sign a corporate
version of this agreement naming the employees who may contribute. Open
an issue titled "CCLA request" and the Maintainer will send it.

## Reporting a security issue

Provisio mints tokens and evaluates authorization, so a bug in either
matters even though it only ever runs locally. Please report security
issues privately to the Maintainer (contact in the repository profile)
rather than in a public issue, and allow a fix before disclosure.
