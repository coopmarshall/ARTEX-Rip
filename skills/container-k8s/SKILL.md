---
name: container-k8s
description: "Invoke this skill when the task needs to find and verify container and orchestration misconfiguration on an authorized target: an exposed Docker Engine API or container registry, an exposed Kubernetes API server/kubelet/dashboard, over-permissive RBAC, privileged or hostPath-mounted pods, and container escape vectors reachable from inside a compromised container. Complements cloud-recon (cloud-provider resource/IAM misconfiguration); this skill's focus is the container runtime and orchestrator layer itself."
---

# Container & Kubernetes Misconfiguration

Under an **authorized** engagement, find and verify container-runtime and
orchestrator misconfigurations — without disrupting workloads that are not
yours. The standing finding quality gates and the adversarial gate in your
system prompt apply throughout: an exposed API or an over-broad RBAC binding
is a lead until a concrete, minimal, non-destructive action against it is
observed and recorded as evidence.

Attribution: original to this repository, written for ARTEX's existing
verified-findings pipeline (`poe_level`, `verification_status`,
`verification_note`) and the same boundary conventions as cloud-recon and
secrets-hunting.

## Boundaries and authorization

| Allowed | Prohibited |
|---|---|
| Querying an exposed Docker/Kubernetes API for version and inventory info (`docker version`, `docker ps`, `kubectl get pods --all-namespaces` with discovered/default credentials) | Starting, stopping, deleting, or modifying any container, pod, deployment, or node belonging to the target |
| Launching a disposable container *of your own* to demonstrate a runtime escape or socket-mount abuse, in a lab you control | Launching a container on the target's own cluster/daemon, even a "harmless" one — that is a workload change, not a read |
| Reading RBAC bindings, pod specs, and admission-controller config to characterize excess privilege | Using a captured service-account token or kubelet credential to pivot beyond the one proof call needed to document the finding |
| Reporting registry contents (image names/tags) already pullable without authentication | Pulling and redistributing proprietary image contents beyond what is needed to prove the registry is open |

A workload, secret, or node that is reachable but clearly belongs to another
tenant on shared infrastructure (a multi-tenant cluster you were not engaged
to test) is out of scope — stop and report the boundary rather than
continuing to enumerate it.

## Phase 1: find exposed control surfaces

- [ ] **Docker Engine API**: TCP 2375 (unauthenticated) / 2376 (TLS) — `curl http://<host>:2375/version`, `curl http://<host>:2375/containers/json`. An open 2375 with no client-cert requirement is a full-host-compromise-grade finding on its own (the API can create a privileged container).
- [ ] **Kubernetes API server**: TCP 6443/8080 — `curl -k https://<host>:6443/version`; an anonymous-auth-enabled or misconfigured RBAC-bypassed server answers `kubectl --server=... --insecure-skip-tls-verify get pods` with no credentials.
- [ ] **kubelet API**: TCP 10250 (authenticated) / 10255 (historically read-only, deprecated but still seen) — `curl -k https://<host>:10250/pods`, `curl http://<host>:10255/pods`. The kubelet's `/exec`, `/run`, `/attach` endpoints allow arbitrary command execution in a pod's containers if reachable without authorization.
- [ ] **Container registries**: `curl https://<registry>/v2/_catalog` (Docker Registry v2 API) for an unauthenticated catalog listing; `curl https://<registry>/v2/<repo>/tags/list` per repository found.
- [ ] **Dashboards and management UIs**: Kubernetes Dashboard, Portainer, Rancher, left reachable without authentication or with default credentials.
- [ ] **etcd**: TCP 2379 — `etcdctl --endpoints=<host>:2379 get / --prefix --keys-only` on an unauthenticated endpoint exposes the entire cluster state, including secrets.

## Phase 2: characterize privilege, once inside or once control-plane access exists

RBAC:

- [ ] `kubectl auth can-i --list` under whatever credential was obtained — the single most informative read-only command for scoping what the credential can actually do.
- [ ] look for `cluster-admin` bound to a default service account, a wide wildcard rule (`resources: ["*"], verbs: ["*"]`), or a role bound to `system:authenticated`/`system:unauthenticated`.

Pod and workload specs:

- [ ] `privileged: true` containers.
- [ ] `hostPath` mounts of sensitive host paths (`/`, `/var/run/docker.sock`, `/etc`).
- [ ] `hostNetwork`/`hostPID`/`hostIPC: true`.
- [ ] containers running as root with no `allowPrivilegeEscalation: false` / no seccomp or AppArmor profile.
- [ ] a mounted `/var/run/docker.sock` inside a container is a direct escape to the host's Docker daemon — treat finding the mount as sufficient; demonstrating the escape itself only needs one `docker version` call through the socket, not a full host takeover.

Secrets:

- [ ] Kubernetes `Secret` objects readable by an over-broad role; environment variables and mounted secret files inside pods you can already inspect.
- [ ] service-account tokens auto-mounted into pods that do not need API access (`automountServiceAccountToken` not disabled where it should be).

## Phase 3: verification before reporting

- [ ] an exposed API finding needs the actual unauthenticated response (version/inventory output), not just "the port is open" from a port scan.
- [ ] an RBAC-overreach finding needs the `can-i --list` output or the binding's YAML, not an assumption from the role's name.
- [ ] a container-escape finding (socket mount, privileged pod) needs the pod spec confirming the mount/flag, plus — only if a disposable lab container is available — a reproduced escape; otherwise report the configuration as `unverified` with the spec as evidence and the escape as the inferred (not observed) impact.
- [ ] record `poe_level`/`verification_status` per the existing finding workflow, and `counterevidence` when a control-plane component is intentionally exposed behind a separate network boundary not visible from the test vantage point.

## Tools

| Tool | Use | Notes |
|---|---|---|
| `kubectl` | cluster inspection and RBAC simulation (`auth can-i`) | always prefer the read-only subcommands first |
| `docker` CLI against a discovered remote `DOCKER_HOST` | Engine API inspection | never used to create/modify the target's containers |
| `curl` | direct unauthenticated probes against API/registry/dashboard endpoints | always available |
| `kube-hunter`, `kube-bench` | automated cluster misconfiguration and CIS-benchmark scanning | verify availability and program policy before running an automated scanner against a live cluster |
| `etcdctl` | etcd inspection when reachable unauthenticated | read-only (`get`), never `put`/`del` |

## Completion self-check

- [ ] every reported exposure is backed by an actual observed response, not a port-scan inference
- [ ] no container, pod, deployment, node, or etcd key belonging to the target was created, started, stopped, modified, or deleted
- [ ] any credential or token obtained during testing was used only for the minimal proof call, never for further pivoting without separate authorization
- [ ] workloads or tenants outside the authorized scope were left untouched and reported, not probed
