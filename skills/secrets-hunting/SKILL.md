---
name: secrets-hunting
description: "Invoke this skill when the task needs to find exposed credentials and secrets on an authorized target: API keys and tokens in JS bundles or source maps, cloud credentials in config/backup files or container layers, secrets committed to an exposed .git directory or accessible repo history, verbose error messages leaking connection strings, and cloud metadata SSRF (169.254.169.254) reachable through a target-side request. Covers finding and minimally verifying a secret; it is not a credential-stuffing or lateral-movement skill."
---

# Secrets Hunting

Under an **authorized** engagement, find credentials and secrets the target
exposes, and verify each one just enough to prove it is real and live — no
further. The standing finding quality gates and the adversarial gate in your
system prompt apply throughout: a string that merely *looks* like a key is a
lead, not a finding, until verification binds it to a live effect.

Attribution: original to this repository, written for ARTEX's existing
verified-findings pipeline (`poe_level`, `verification_status`,
`verification_note`; see the finding workflow).

## Boundaries and authorization

| Allowed | Prohibited |
|---|---|
| Finding a secret through recon already in scope (JS/source maps, exposed `.git`, backups, verbose errors, container layers, cloud metadata reached *from the target*) | Social engineering, phishing, or physical access to obtain a secret |
| One minimal, read-only authenticated call to prove a credential is live (e.g. `aws sts get-caller-identity`, a single GET against the API it unlocks) | Using a found credential to write, delete, enumerate broadly, or pivot into systems outside the written scope |
| Capturing redacted evidence (first/last 4 chars, key type, scope revealed by the verification call) | Storing or reporting a secret unredacted; downloading data the credential exposes beyond the one proof call |
| Reporting the exposure path and blast radius | Rotating, revoking, or modifying the credential or anything it protects |

A credential that unlocks access beyond the current task's scope is an
immediate stop-and-report, not an invitation to keep going: open a finding
noting the scope boundary and let the human decide whether to extend
authorization before any further verification call is made.

## Where secrets hide

### Phase 1: static surface (no target interaction beyond normal fetch)

- [ ] JS bundles: search for `AKIA[0-9A-Z]{16}`, `-----BEGIN [A-Z ]*PRIVATE KEY-----`, `sk_live_`, `sk_test_`, `xox[baprs]-`, `ghp_`, `glpat-`, `AIza[0-9A-Za-z_-]{35}`, `eyJ[A-Za-z0-9_-]{10,}\.eyJ` (JWT), bare `Bearer `/`Authorization:` strings, and hardcoded `.env`-style `KEY=value` blocks bundled by mistake.
- [ ] Source maps (`*.js.map`): if exposed, they reconstruct original source, including comments and inline constants a minifier would otherwise hide.
- [ ] Config and backup files: `.env`, `.env.*`, `config.json`, `web.config`, `appsettings.json`, `*.bak`, `*.swp`, `*.orig`, `~` backup copies left by editors, `docker-compose.yml` with inline env blocks.
- [ ] Exposed `.git`: `GET /.git/config` as the canary; if reachable, `git-dumper` or a manual `.git/objects` walk reconstructs the tree without ever needing `git clone` against the live server, then `gitleaks detect` / `trufflehog filesystem` against the reconstructed tree.
- [ ] Build artifacts and CI leftovers: `/.github/workflows/*.yml` served as a static file, `/.circleci/config.yml`, Jenkinsfiles, all of which sometimes embed deploy credentials directly instead of referencing a secret store.

### Phase 2: dynamic surface (normal authorized requests)

- [ ] Verbose error pages and stack traces: force one (malformed input, wrong `Content-Type`, an intentionally invalid id) and read for connection strings, internal hostnames, and file paths.
- [ ] Debug/introspection endpoints left enabled: `/actuator/env`, `/debug/vars`, `/_profiler`, `/phpinfo.php`, GraphQL introspection fields that echo server config.
- [ ] Response headers and timing: `Server`, `X-Powered-By`, cache headers revealing an internal CDN key, cookies carrying an unsigned or weakly-signed session that itself holds secrets.
- [ ] Cloud metadata SSRF: any parameter that makes the **target** fetch a URL (webhook registration, avatar-by-URL, PDF/image render, SSO redirect) — probe with the metadata endpoint for the cloud the target is hosted on (AWS/GCP `169.254.169.254`, Azure `169.254.169.254/metadata`, Alibaba `100.100.100.200`) and read back only what proves reachability (the credential's expiry and role name is enough; do not fetch the credential body unless demonstrating impact requires it).

### Phase 3: container and artifact layers (only when an image is in scope)

- [ ] `docker history --no-trunc <image>` for `ENV`/`ARG` layers baking in secrets at build time.
- [ ] `dive <image>` or `docker save | tar -xO` to inspect individual layer filesystems for leftover `.env`/`id_rsa`/`.npmrc` files that a later layer deleted but did not squash out.
- [ ] Multi-stage build leaks: a secret copied into an early stage and never referenced again still exists in that stage's layer.

### Phase 4: verification (the only step that turns a lead into a finding)

A candidate secret is unverified until one of these is observed and the
observation is recorded as the finding's evidence:

- [ ] Cloud key: one identity call (`aws sts get-caller-identity`, `gcloud auth list` after `gcloud auth activate-service-account`, `az account show`) — record the account/project id and attached role name, not a resource dump.
- [ ] API token: one read-only call against the API it is scoped to (fetch the authenticated user's own profile, not another user's).
- [ ] Private key: confirm it matches a certificate or known public key already observed on the target (`openssl x509 -noout -modulus` / `ssh-keygen -y`) rather than attempting to use it to authenticate anywhere.
- [ ] JWT signing key found in source/config: forge a token for a test account the engagement controls and confirm the target accepts it; never forge a token impersonating a real user.

Record `poe_level` and `verification_note` per the existing finding workflow;
a secret that fails every verification path above is reported, if at all, as
`unverified` with the exposure path as the evidence and no claim of a live
credential.

## Tools

| Tool | Use | Notes |
|---|---|---|
| `gitleaks detect` | regex + entropy scan of a filesystem or git history | fast, low false-negative on common key formats |
| `trufflehog filesystem` / `trufflehog git` | scan with live-verification plugins for many providers | prefer this when a provider-specific verifier exists, it does Phase 4 for you |
| `git-dumper` | reconstruct a tree from an exposed `.git` directory | verify availability before promising a dump |
| `rg -n` with the Phase 1 regex list | quick manual sweep of fetched JS/config when the above tools are unavailable | always available |
| cloud CLIs (`aws`, `gcloud`, `az`) | the Phase 4 identity call only | never anything beyond the one proof call without written authorization |

## Completion self-check

- [ ] every candidate secret is either verified live (with a recorded, minimal proof call) or explicitly reported as unverified
- [ ] no secret value appears unredacted anywhere in the work dir or report
- [ ] no verification call wrote, deleted, or enumerated beyond what proving liveness required
- [ ] any access reaching beyond the task's scope was stopped and reported, not pursued
