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
