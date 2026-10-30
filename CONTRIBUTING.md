# Contributing

Thanks for your interest. This is a deliberately small, security-sensitive
service, so changes favor explicit checks and tests over features.

## Development setup

```sh
npm ci --ignore-scripts
npm test                       # all tests are offline: no network, credentials or database
npm audit
python3 scripts/audit_repo.py  # secret/identifier audit of the index and Git history
```

Node.js 24 is required (see `engines` in `package.json`). If you have
[Gitleaks](https://github.com/gitleaks/gitleaks), also run `gitleaks git .`.

## Pull requests

- Keep each pull request focused, and describe the behavior change and its
  security reasoning.
- Add or update tests for every behavior change. Tests use in-memory stores,
  fake pools and fake transports; never use real tokens, endpoints or secrets.
- Preserve fail-closed behavior: new configuration must reject invalid input
  rather than guess a default, and no request value may select an issuer,
  destination, secret, peer or permission.
- **Compatibility mode** (`BRIDGE_PUBLIC_ORIGIN` unset) must keep producing the
  original deployment's exact wire contract; `test/compat-contract.test.mjs`
  pins it. Generic deployments are exercised by
  `test/generic-deployment.test.mjs` in a child process, because deployment
  identity is read once at startup.
- Keep dependencies minimal and pinned to exact versions.
- Do not commit `.env` files, reports, transcripts or message history; see
  `.gitignore`.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not file public issues for
vulnerabilities.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
