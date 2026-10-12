# Getting help

mailctl is maintained in spare time by one person. Pick the channel that
fits so questions get an answer and bugs get fixed.

| You want to | Go to |
|---|---|
| Learn how something works | The [manual](https://zoolcoder.github.io/mailctl/), starting with [troubleshooting](https://zoolcoder.github.io/mailctl/mailctl/troubleshooting.html) |
| Report a bug or a skill that misbehaved | [New issue](https://github.com/ZoolCoder/mailctl/issues/new/choose), with `mailctl doctor` output |
| Ask for a provider or a feature | [Feature request](https://github.com/ZoolCoder/mailctl/issues/new/choose) |
| Ask a question or share how you use it | [GitHub Discussions](https://github.com/ZoolCoder/mailctl/discussions) |
| Report a security problem | [SECURITY.md](SECURITY.md), never a public issue |
| Contribute code, docs or a skill | [CONTRIBUTING.md](CONTRIBUTING.md) |

## Before you ask

1. Run `mailctl doctor`. It names the broken step and how to fix it.
2. Run `mailctl version` and check the [releases page](https://github.com/ZoolCoder/mailctl/releases) for a newer one.
3. Search the existing issues.

## What to include

- `mailctl doctor` and `mailctl version` output.
- Platform, the providers involved, and the agent if one was used.
- The smallest config that reproduces it, with domains replaced by `example.com`.

Never paste a token, a `*.secrets` file, a mailbox password or an app
credential. Redact real domains and addresses.

## Response time

Issues are read within a week. There is no paid support and no SLA; fixes
land in the next release.
