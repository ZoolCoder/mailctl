## What

<!-- One topic, and why. Link the issue: Closes #123 -->

## Checklist

- [ ] `make test` and `make lint` pass, `gofmt -l .` prints nothing
- [ ] Targets `develop`; only `release/*` and `hotfix/*` target `main`
- [ ] Conventional commit messages, rebased on `develop`
- [ ] No new non-stdlib dependency, or the pull request explains why one is unavoidable
- [ ] `Plan` still performs no I/O: all I/O is inside an action's closure
- [ ] Config a provider cannot honour is rejected in `config.Validate`, not ignored
- [ ] Touches a credential path: called out above. No credential reaches stdout or an MCP reply
- [ ] New command or JSON shape: golden test, `commands.adoc` in `docs/en` and `docs/ar`, and `adapters/cloud/AGENTS.md` updated
- [ ] New or changed skill: eval case under `evals/` when it applies, prunes or handles credentials
- [ ] No real domain, address or provider ID in tests or fixtures: `example.com` only
