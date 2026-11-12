# Contributing

Thanks for your interest. This is a deliberately small, security-sensitive
service, so changes favor explicit checks and tests over features.

## Development setup

```sh
npm ci --ignore-scripts
npm run typecheck              # strict TypeScript (tests and fixtures included)
npm run compile:check          # clean emit to dist/ and load the emitted entry points
npm test                       # all tests are offline: no network, credentials or database
npm audit
python3 scripts/audit_repo.py  # secret/identifier audit of the index and Git history
```

Node.js 24.22.3 or newer within major 24 is required (see `engines` in
`package.json`). The source is TypeScript that Node 24 runs directly (type
stripping, so only erasable syntax: no enums, namespaces or parameter
properties) and Vercel compiles at deploy time; there is no build step to
run before deploying. Vercel does not type-check, so `npm run typecheck` (also
run in CI) is the gate: keep `strict` and the other compiler checks on, and
do not add `any`, `@ts-ignore` or `@ts-expect-error`. If you have
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
  original deployment's exact wire contract; `test/compat-contract.test.ts`
  pins it. Generic deployments are exercised by
  `test/generic-deployment.test.ts` in a child process, because deployment
  identity is read once at startup.
- Keep dependencies minimal and pinned to exact versions.
- The CodeQL workflow is skipped while the repository is private (code
  scanning there requires GitHub Advanced Security) and runs automatically
  once it is public.
- Do not commit `.env` files, reports, transcripts or message history; see
  `.gitignore`.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not file public issues for
vulnerabilities.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
