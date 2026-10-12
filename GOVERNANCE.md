# Governance

## Roles

- **Maintainer**: [@ZoolCoder](https://github.com/ZoolCoder). Reviews and merges pull
  requests, triages issues, cuts releases, handles security reports and
  conduct reports.
- **Contributor**: anyone with a merged pull request or an accepted skill.
  Listed in the release notes.

A contributor with several merged changes and a track record of review can
be invited as a maintainer. Maintainers get write access to the repository
and share the duties above.

## Decisions

Changes are discussed in the issue before the pull request. The maintainer
decides when there is no consensus. These points are not up for a vote:

- The CLI stays the contract between people, skills, the MCP server and the UI.
- Planning performs no I/O, and nothing is applied that was not shown first.
- No skill or MCP tool applies, prunes or creates a credential without the
  user saying yes after seeing the plan.
- A generated credential never reaches stdout, a log or an agent reply.
- No telemetry, no accounts, no required cloud service.

## Releases

Semantic versioning and git flow, described in
[CONTRIBUTING.md](CONTRIBUTING.md#branches). Work lands on `develop` through
pull requests. A release is a `release/X.Y.Z` branch from `develop` that
updates `CHANGELOG.md`, merged into `main`, tagged `vX.Y.Z` there, which
triggers the release workflow, and merged back into `develop`. The release
workflow commits the Homebrew cask to `develop`, the default branch, which is
the one `brew tap` clones. Hotfixes
branch from `main` as `hotfix/X.Y.Z` and merge back into both. Only the
maintainer can push a `v*` tag. Breaking
changes to the config format, the CLI flags or the JSON output bump the
minor version before 1.0 and the major version after.

## Changing this document

Open an issue first. Changes to governance, the code of conduct or the
security policy are announced in the release notes.
