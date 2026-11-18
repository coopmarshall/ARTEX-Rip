---
name: cloud-recon
description: "Invoke this skill when the task needs to map an authorized target's cloud footprint and check it for misconfiguration: object storage buckets (S3/GCS/Azure Blob) with weak ACLs, IAM role trust and permission misconfiguration, exposed management/admin planes, and SSRF-reachable instance metadata. Complements bbot-recon (DNS/subdomain breadth) and secrets-hunting (credential exposure); this skill's focus is cloud-provider-specific resource and permission misconfiguration."
---

# Cloud Recon (AWS / GCP / Azure misconfiguration)

Under an **authorized** engagement, map which cloud resources an organization
exposes and check them for misconfiguration — without ever modifying,
deleting, or exfiltrating bulk data from what you find. The standing finding
quality gates and the adversarial gate in your system prompt apply
throughout: a bucket or role that merely *exists* and is reachable is a lead;
it becomes a finding only once a concrete, minimal read confirms the
permission boundary is actually broken.

Attribution: original to this repository, written for ARTEX's existing
verified-findings pipeline (`poe_level`, `verification_status`,
`verification_note`) and third-party-intel convention (see bbot-recon's
`source=third_party_intel` handling for out-of-scope discoveries).

## Boundaries and authorization

| Allowed | Prohibited |
|---|---|
| Listing a bucket/container's contents to confirm an ACL is actually public | Downloading bulk data beyond the one or two objects needed to prove impact |
| Reading object names/metadata to characterize what is exposed (PII, backups, source, secrets) | Deleting, overwriting, or uploading to any discovered resource — even to "prove write access", a `PutObject` dry run against a disposable test key is the limit |
| One minimal identity/permission-enumeration call against an assumed or discovered role (`sts get-caller-identity`, `iam simulate-principal-policy`) | Chaining a discovered role into further privilege escalation beyond what is needed to document the initial misconfiguration, without separate authorization |
| Reaching instance metadata **through a target-side SSRF** you already control (see secrets-hunting Phase 2) | Probing cloud metadata endpoints from your own tester host — that only tells you about your own infrastructure, not the target's |
| Reporting the resource identifier, the permission that is wrong, and the minimal evidence | Public-shaming scans unrelated to the task's actual scope (unauthenticated internet-wide bucket sweeps are not "recon on an authorized target") |

A resource that is misconfigured but clearly belongs to an unrelated third
party (shared hosting, a CDN-fronted bucket not owned by the target) is out
of scope — report it as a third-party intel note if relevant, never probe it
further.

## Phase 1: enumerate the footprint

- [ ] **Bucket/container name guessing** from the organization's known names: `<company>`, `<company>-backup`, `<company>-prod`, `<company>-assets`, `<company>-logs`, `www-<company>`, permutations of domains already in scope. Tools: `s3scanner`, `cloud_enum`, or manual `aws s3 ls s3://<name>` / `curl https://<name>.s3.amazonaws.com` / `curl https://storage.googleapis.com/<name>` / `curl https://<account>.blob.core.windows.net/<name>?restype=container&comp=list`.
- [ ] **DNS and certificate leads**: CNAMEs pointing at `*.s3.amazonaws.com`, `*.blob.core.windows.net`, `*.storage.googleapis.com`, `*.cloudfront.net`; SANs on TLS certs naming internal cloud hostnames; this overlaps bbot-recon's output — reuse it rather than re-crawling.
- [ ] **JS bundle / API response leads**: hardcoded bucket URLs, API Gateway/Lambda function URLs, pre-signed URLs with an expiry far in the future, cloud resource ARNs leaked in error messages or client-side config.
- [ ] **Management/admin plane exposure**: a cloud console, Kubernetes dashboard, cloud-native CI runner, or IaC state-file (`terraform.tfstate`, `*.tfvars`) left reachable without authentication.
- [ ] **CDN/takeover surface**: a CNAME pointing at a cloud resource that no longer exists (subdomain/bucket takeover) — report as its own finding class, since claiming the dangling resource is the proof, not a bonus action.

## Phase 2: check what you found

Object storage:

- [ ] list permission: does an unauthenticated or low-privilege request enumerate objects?
- [ ] read permission: can an object be fetched without authentication?
- [ ] write permission: **do not actually write**; a correctly-scoped `PutObject`/upload dry run only against a disposable test key you control, never against the organization's real bucket, proves the same point with zero risk.
- [ ] bucket policy / ACL contents, if readable, often states the misconfiguration explicitly (`Principal: "*"`) — quote it as evidence instead of re-deriving it from behavior alone.

IAM / role trust:

- [ ] an assumed or discovered role's trust policy: does it trust an identity broader than intended (`Principal: "*"`, a wildcard account, an over-broad OIDC subject)?
- [ ] attached policy scope: `iam simulate-principal-policy` (AWS), `gcloud asset analyze-iam-policy` (GCP), or `az role assignment list` (Azure) to characterize what the role can actually do, read-only.
- [ ] instance-profile / workload-identity over-privilege: a compute instance or pod with a role far broader than its function needs (e.g. a web-tier EC2 instance with `AdministratorAccess`).

Metadata SSRF (only via a target-side SSRF, see secrets-hunting Phase 2):

- [ ] confirm reachability and note the role name / project id exposed; do not fetch and use the full credential body unless demonstrating impact specifically requires it, and never pivot with it beyond the one proof call.

## Phase 3: verification before reporting

- [ ] a public bucket/container finding needs one observed unauthenticated `List` or `Get` response, quoted or referenced by request/response artifact — not just "the URL resolves".
- [ ] an IAM misconfiguration finding needs the actual policy document or simulation output showing the excess permission, not an assumption from the role's name.
- [ ] record `poe_level`/`verification_status` per the existing finding workflow; a resource that merely exists and responds (e.g. a bucket returning `AccessDenied`) is `unverified`, not a finding.
- [ ] `counterevidence`: note when a bucket is intentionally public (a CDN origin for public assets) — that is expected behavior, not a finding, unless it also exposes something it should not (backups, PII, source).

## Tools

| Tool | Use | Notes |
|---|---|---|
| `aws`/`gcloud`/`az` CLIs | identity, list, and policy-read calls | read-only calls only; verify credentials are scoped to what the engagement authorizes |
| `s3scanner`, `cloud_enum` | bucket/container name enumeration across providers | verify availability before promising a sweep |
| `curl` | direct unauthenticated probes against storage endpoints | always available |
| `ScopeSentry` asset sync (this platform) | pull already-known cloud hostnames/IPs instead of re-discovering them | see the scopesentry skill |

## Completion self-check

- [ ] every reported resource is identified by its concrete name/ARN/URL, not a guess
- [ ] every finding's evidence is an observed response, policy document, or simulation output — never "the name suggests this is public"
- [ ] no write, delete, or bulk-download action touched a resource you do not own
- [ ] anything reaching beyond the task's authorized scope was stopped and reported, not pursued
