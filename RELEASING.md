# Releasing

The JS SDK (`@g8r-security/agent-shield-sdk`) is published to npm automatically
by the [`Release`](.github/workflows/release.yml) workflow when a `v*` tag is
pushed. You should not need to run `npm publish` from a laptop.

## One-time setup

Add an npm **automation** token as a repository (or org) secret named
`NPM_TOKEN`:

1. On npmjs.com, signed in as a member of the `g8r-security` org with publish
   rights, create an **Automation** access token (Account → Access Tokens →
   Generate New Token → Automation). Automation tokens bypass 2FA, which is what
   lets CI publish non-interactively.
2. In this repo: Settings → Secrets and variables → Actions → New repository
   secret → name `NPM_TOKEN`, value the token.

The workflow publishes with `--provenance`, which attests on npm that the
package was built from this repo at this commit. That requires the `id-token:
write` permission (already set in the workflow) and a public repo (this one).

## Cutting a release

From `main`, with a clean tree:

```bash
cd js
npm version patch     # or minor / major — bumps package.json and creates the vX.Y.Z tag
git push --follow-tags
```

`npm version` commits the bump and creates a matching `vX.Y.Z` tag. Pushing the
tag triggers the `Release` workflow, which:

1. runs typecheck, the unit tests, and the consumer smoke test,
2. verifies the tag matches `package.json`'s version,
3. publishes to npm with provenance.

Watch the run under the repo's **Actions** tab. If any gate fails, nothing is
published — fix forward and push a new tag.

## Deprecating a bad version

If a published version has a defect, point consumers at the fix:

```bash
npm deprecate @g8r-security/agent-shield-sdk@"<X.Y.Z" "Upgrade to >=X.Y.Z — <reason>."
```

---

# Python SDK (`g8r-shield` on PyPI)

Published by the [`Publish Python`](.github/workflows/publish-python.yml) workflow
when a **`py-v*`** tag is pushed. The `py-` prefix keeps it distinct from the JS
SDK's `v*` tags so one tag never triggers both publishers. Auth is **PyPI Trusted
Publishing (OIDC)** — no API token is stored anywhere (the manual `twine upload`
path below is only needed for the very first publish or a break-glass release).

## One-time setup (PyPI trusted publisher)

On PyPI, signed in as an owner of the `g8r-shield` project:
**Manage → Publishing → Add a new publisher** (GitHub), with:

- Owner: `Gator-Security`
- Repository: `g8r-agent-shield-sdk`
- Workflow name: `publish-python.yml`
- Environment: *(leave blank, or set one and add it to the workflow)*

(If the project did not yet exist you'd use a *pending publisher* with the same
fields; here the project already exists, so add it as a normal publisher.)

## Cutting a release

From `main`, clean tree, bump BOTH version locations to the same value:

- `python/pyproject.toml` → `version`
- `python/g8r_shield/_version.py` → `_FALLBACK_VERSION`

then:

```bash
git commit -am "python sdk: vX.Y.Z"
git tag py-vX.Y.Z
git push --follow-tags
```

The workflow runs ruff + mypy + pytest, asserts the tag matches `pyproject`'s
version AND that `pyproject` and `_version.py` agree, builds sdist+wheel,
`twine check`s them, and publishes to PyPI via OIDC. Any gate failing publishes
nothing.

## Manual publish (first release / break-glass)

Build and upload with a token from `~/.pypirc` (`[pypi]`/`[testpypi]` sections,
`username = __token__`). Dry-run on TestPyPI first:

```bash
cd python
python -m build
twine check dist/*
twine upload --repository testpypi dist/*   # dry run
twine upload dist/*                          # real PyPI
```

## Yanking a bad version

PyPI can't delete, but you can **yank** (hides from new installs, keeps existing
pins working): project page → Manage → the release → **Yank**.
