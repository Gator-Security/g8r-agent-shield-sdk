# Changelog

## 0.7.0

Breaking change. The SDK no longer accepts a shared or default deployment secret.

### Migration

- Stop setting `G8R_API_KEY`. Pass exactly one per-tenant credential at runtime:
  `api_key` / `apiKey`, `credential_file` / `credentialFile`, `credential_env` /
  `credentialEnv`, or `credential_provider` / `credentialProvider`. If you pass
  none of those, set exactly one of `G8R_TENANT_CREDENTIAL` or
  `G8R_TENANT_CREDENTIAL_FILE`. Two clients in one process do not share a
  credential.
- `console_url` / `consoleUrl` and `pep_url` / `pepUrl` must use `https`. Both
  refuse loopback hosts. Set `G8R_ALLOW_INSECURE_LOCALHOST=1` only on a
  developer machine to permit `http://localhost`, `http://127.0.0.1`, and
  `http://[::1]` (https on those hosts is allowed too). Any other host still
  has to be `https`.
- `tenant_id` / `tenantId` must contain a non-whitespace value.

### Security

- `console_url` goes through the same loopback refusal as `pep_url`.
- `credential_provider` / `credentialProvider` failures are no longer chained
  as the error cause, so a token embedded in the provider exception is not
  printed with the traceback.
- The TypeScript client loads `node:fs` only when a credential file is read,
  so browser and edge bundles are not forced to resolve it.
