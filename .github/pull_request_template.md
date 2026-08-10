## What this changes

<!-- and why. Link the issue if there is one. -->

## Checklist

- [ ] `gofmt -l .` prints nothing, `go vet ./...` is clean, `go test ./...` passes
- [ ] No new non-stdlib dependency, or the pull request explains why one is unavoidable
- [ ] `Plan` still performs no I/O — all I/O is inside an action's closure
- [ ] Any config a provider cannot honour is rejected in `config.Validate` rather than ignored
- [ ] Errors name the object and what the operator should do about it
- [ ] If this touches a credential path, it is called out above so it gets proper attention
- [ ] If this adds or changes a test guarding a safety property, it has been
      mutation-checked: the code was broken deliberately and the test observed to fail
