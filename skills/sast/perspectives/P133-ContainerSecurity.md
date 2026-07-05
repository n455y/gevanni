---
id: P133
name: ContainerSecurity
refs: ASVS V15.x / WSTG-CONF / CS: Docker Security
requires: []
---

# P133 — Container Security

## Overview
Container and Infrastructure-as-Code (IaC) misconfigurations turn a hardened application into a trivially compromised one, because they collapse the isolation boundary the runtime is expected to provide. The root cause is almost always defaults: most base images run as root, ship a writable root filesystem, and trust `:latest` tags — while Kubernetes workloads get a permissive `ClusterRole` and no `NetworkPolicy` unless an engineer explicitly opts out. Secrets baked into image layers or environment variables, build contexts that copy `.env`/`.git/credentials`, and `hostPath`/`privileged` mounts widen a single container escape into host takeover and lateral movement across the cluster. Reviewing the Dockerfile, Helm chart, Kustomize manifests, and CI build definition is therefore as load-bearing as reviewing the application code.

## What to check
- Does the image run as **root** (no `USER` directive, or `USER 0`/`USER root`)? Is a non-root UID specified by numeric ID (not a name that may still resolve to 0)?
- Is the container `privileged: true`, or does it request a broad capability set (`--cap-add SYS_ADMIN`, `SYS_PTRACE`, `NET_ADMIN`, `DAC_READ_SEARCH`)?
- Is the **root filesystem writable** (`readOnlyRootFilesystem` absent/false)? Are `/tmp`, caches, or logs mounted `emptyDir`/`tmpfs` to keep the root fs read-only?
- Is the base image pinned by **immutable digest** (`image: nginx@sha256:...`) or only by mutable tag (`:latest`, `:1.25`)? Mutable tags are vulnerable to supply-chain swap.
- Are **secrets** present in the image (env vars in Dockerfile `ENV`, `ARG` values leaked into history, `COPY .env`, baked TLS keys/tokens) instead of runtime injection (K8s `Secret`, Vault, cloud KMS/ Secrets Manager)?
- Is **user namespace remapping** disabled, so UID 0 in the container == UID 0 on the host?
- Are there **`hostPath`** volume mounts (`/var/run/docker.sock`, `/`, `/etc`, `/proc`) that expose the host kernel/daemon to the container?
- Is Kubernetes **RBAC** absent, or does a workload `ServiceAccount` use `cluster-admin` / a `*` `verbs`/`resources` `ClusterRole(Binding)`?
- Are **NetworkPolicies** absent, leaving every pod able to reach every other pod (and the metadata service / egress)?
- Are **resource limits** (`resources.limits.cpu`/`.memory` and `requests`) missing, enabling a noisy-neighbor or malicious pod to exhaust node resources (DoS / evictions)?
- Does the Dockerfile use `ADD <url>` (fetches remote content, auto-extracts tar, no integrity check) instead of `COPY` + verified checksum?
- Does the **build context** leak secrets (no `.dockerignore`, `COPY . .` copying `.git/`, `.env`, `~/.aws/credentials`, SSH keys into a layer that may be published)?
- Is `seccomp`/`AppArmor`/`SELinux` disabled (`securityContext: seccompProfile: Unconfined`)?
- Does the image run a shell-as-init (`CMD ["sh","-c",...]`) instead of a PID-1 reap loop, leaving zombies and ignoring signals?

## Static signals
Dockerfile:
- No `USER` line, or `USER root` / `USER 0`
- `FROM node:latest` / `FROM python:latest` (mutable, fat base)
- `ENV DB_PASSWORD=...` / `ARG GH_TOKEN=ghp_...` / `ENV AWS_SECRET_ACCESS_KEY=...`
- `ADD https://...` (remote fetch, no checksum)
- `RUN chmod 777` / `RUN chown -R root:root /app && chmod 777 /app`
- `COPY . .` / `COPY . /app` with no `.dockerignore`
- `CMD npm start` (string form → `/bin/sh -c`, shell as PID 1)

Kubernetes / Helm / Kustomize YAML:
- `privileged: true`
- `readOnlyRootFilesystem: false` (or omitted under a default-allowant policy)
- `runAsUser: 0` / `runAsNonRoot: false`
- `allowPrivilegeEscalation: true`
- `hostPath:` volumes, esp. `path: /var/run/docker.sock`, `/`, `/proc`, `/etc/kubernetes`
- `hostNetwork: true`, `hostPID: true`, `hostIPC: true`
- `image: registry/app:latest` (no `@sha256:`)
- `kind: ClusterRoleBinding` with `cluster-admin`, or `verbs: ["*"]` `resources: ["*"]`
- No `NetworkPolicy` resources at all
- `resources:` block missing or with only `requests` (no `limits`)
- `secrets:` referenced inline, or `env:` containing `SECRET`/`TOKEN`/`PASSWORD` literals
- `automountServiceAccountToken: true` (default) on pods that don't need API access

docker-compose / docker run:
- `user: root`, `privileged: true`, `cap_add: [SYS_ADMIN]`
- `volumes: ["/:/host"]`, `"/var/run/docker.sock:/var/run/docker.sock"`
- `secrets`/passwords in `environment:`

Terraform/Pulumi (IaC):
- `container_definitions` with `"privileged": true`, `"readonlyRootFilesystem": false`
- EKS/GKE node pools with no PodSecurityPolicy/AdmissionController, image pull policy `Always` on `:latest`

## False positives
- A base image that ships a non-root user and the Dockerfile sets `USER 1001` (verify with `docker inspect` / `id` inside the image — a numeric non-zero UID is the only reliable signal).
- `privileged`/`hostPath`/`hostNetwork` on a node-level DaemonSet that genuinely requires it (CNI, CSI, log shipper, kube-proxy) and is isolated via taints/namespaces — confirm the blast radius is documented and the SA is scoped.
- Mutable tag in a *dev* cluster where image freshness is intentional and an admission controller (e.g. Kyverno/OPA) enforces digest resolution at admission; the policy, not the tag, is the control.
- Secrets in env vars that are sourced from a managed secret store at runtime (K8s `secretKeyRef`, AWS Secrets Manager, Vault agent) rather than literal values — the literal in the manifest is the smell.
- Missing resource limits because a cluster-wide `LimitRange`/`ResourceQuota` applies defaults — check cluster-level policy before flagging.

## Attack scenario
1. The image runs as root (`USER` omitted) and mounts `/var/run/docker.sock` "for logging".
2. An attacker exploits an SSRF, RCE, or deserialization bug in the app to get code execution inside the container as UID 0.
3. Because user namespace remapping is off, UID 0 in the container is UID 0 on the host. The attacker talks to the Docker socket: `curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json`.
4. They launch a malicious container mounting the host root: `docker run -v /:/host -it alpine chroot /host`, granting full host filesystem access.
5. With `privileged: true` and `allowPrivilegeEscalation`, they load a kernel module or read `/etc/shadow`, steal cloud instance credentials from the IMDS endpoint (169.254.169.254), and pivot.
6. The pod's `ServiceAccount` token (automounted, `cluster-admin`) is used to read all `Secrets` across namespaces and spawn pods on every node — cluster-wide compromise.

## Impact
- **Confidentiality**: host filesystem and cloud-credential theft, exfiltration of every Secret in the cluster via an over-permissioned ServiceAccount.
- **Integrity**: container escape → host compromise → tamper with sibling containers, deploy backdoor images, modify CI/CD pipelines.
- **Availability**: a container without resource limits can exhaust node CPU/memory (fork bomb, memory leak), trigger evictions and node-level DoS; a `privileged` pod can crash the kernel.
- Severity scales with the blast radius: a single root/privileged container on a shared node compromises **every** tenant on that node; in managed Kubernetes a stolen node identity can drain or destroy the entire cluster and adjacent cloud resources.

## Remediation
Pin images by digest, drop all capabilities, run as a non-root numeric UID, and make the root filesystem read-only:
```dockerfile
# VULNERABLE — root, mutable, latest tag, secret in layer
FROM node:latest
ENV DB_PASSWORD=s3cret
COPY . .
EXPOSE 3000
CMD npm start

# HARDENED — distroless, digest-pinned, non-root, read-only-friendly
FROM node:22@sha256:<pin-and-verify-digest> AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
FROM gcr.io/distroless/nodejs22-debian12:nonroot@sha256:<digest>
WORKDIR /app
COPY --from=build /app ./
USER 1001:1001
EXPOSE 3000
CMD ["server.js"]
```
```yaml
# VULNERABLE — privileged, hostPath, no limits, automounted token
spec:
  containers:
  - name: app
    image: registry/app:latest
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /var/run/docker.sock
      name: docker-sock

# HARDENED — least privilege
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1001
    fsGroup: 1001
    seccompProfile: { type: RuntimeDefault }
  containers:
  - name: app
    image: registry/app@sha256:<digest>
    resources:
      requests: { cpu: 100m, memory: 128Mi }
      limits:   { cpu: 500m, memory: 512Mi }
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities: { drop: [ALL] }
    volumeMounts:
    - mountPath: /tmp
      name: tmp
  volumes:
  - name: tmp
    emptyDir: {}
```
Apply a Pod Security Admission profile (`restricted`), enforce RBAC least privilege, deny all ingress/egress by default via `NetworkPolicy` with explicit allow rules, and inject secrets at runtime from a managed store (KMS / Vault / cloud Secrets Manager) rather than baking them into images — defense-in-depth across image, runtime, and cluster layers.

## References
- OWASP ASVS V15.x — Secure coding and architecture (component/container hardening)
- OWASP WSTG-CONF — Configuration and deployment management testing
- OWASP Cheat Sheet: Docker Security
