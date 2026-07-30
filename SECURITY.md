# Security Policy: RDMA Core

## Reporting a Vulnerability

If you discover a potential security vulnerability, please **do not open a public issue.**

* Report via: [NVIDIA Vulnerability Disclosure Program](https://www.nvidia.com/en-us/security/) (preferred)
* E-Mail: [psirt@nvidia.com](mailto:psirt@nvidia.com)
  - We encourage you to use the following PGP key for secure email communication:
    [NVIDIA public PGP Key](https://www.nvidia.com/en-us/security/pgp-key)
* GitHub/GitLab: Use the **Security** tab > **Report a vulnerability** to submit a report
  directly on this repository

Please include the following information:
- Product/project name and version/branch
- Type of vulnerability
- Step-by-step reproduction instructions
- Proof-of-concept code (if available)
- Impact assessment

**Detailed reports help NVIDIA evaluate and address issues faster.**

NVIDIA's PSIRT team will acknowledge receipt, validate severity, develop fixes,
and publish security bulletins as appropriate.

## Security Architecture & Context

RDMA Core provides the Linux userspace stack for InfiniBand / RoCE / iWARP:
shared libraries (`libibverbs`, `librdmacm`, `libibumad`, `libibmad`), hardware
provider plugins under `providers/` (including mlx4/mlx5, rxe, siw, efa, and
others), Python bindings (`pyverbs`), diagnostic CLIs (`infiniband-diags`), and
privileged support daemons (`ibacm`, `iwpmd`, `srp_daemon`, `rdma-ndd`).

This software operates at the **Library / SDK** and **privileged daemon** level.
Its primary security responsibility is to mediate userspace access to RDMA
devices (`/dev/infiniband/uverbs*`, `rdma_cm`, `umad*`) so applications can
register memory, post work requests, and establish RDMA connections without
bypassing kernel/hardware isolation—and so support daemons do not become
unauthenticated control planes for fabric or host networking.

**Repository Exposure Classification:** Internal.
Basis: origin remote is an internal NVIDIA forge (`git-nbu.nvidia.com`, `mlnx_ofed/rdma-core`).

**Service Exposure Classification:** External / Regulated (high confidence).
Basis: externally distributed OFED/enterprise and distro userspace RDMA stack;
customer-facing libraries and daemons that form part of the RDMA memory and
device security boundary.

Key security boundaries and interfaces:
- **Kernel uverbs/ioctl/mmap path** — `libibverbs` and providers issue commands
  and map device memory via `ioctl` / `mmap` on RDMA char devices; authorization
  and object lifetime are enforced primarily by the kernel RDMA subsystem.
- **Provider plugin loading** — `libibverbs/dynamic_driver.c` `dlopen`s provider
  shared objects from `VERBS_PROVIDER_DIR`, the system library path, or
  `RDMAV_DRIVERS` / `IBV_DRIVERS` (when not setuid).
- **Memory registration & remote keys** — `ibv_reg_mr`, `ibv_reg_dmabuf_mr`,
  import/export MR APIs, and provider-specific crypto/DEK objects (mlx5 AES-XTS)
  determine which host memory and keys are reachable over the fabric.
- **Privileged daemons** — `ibacm` (path/name resolution over Unix/TCP + RDMA
  netlink), `iwpmd` (iWARP port mapping over netlink/UDP), `srp_daemon` (SRP
  target discovery), `rdma-ndd` (node description updates).
- **Socket interception** — `librdmacm/preload.c` can replace libc socket APIs
  via `LD_PRELOAD`.
- **Application / pyverbs / examples** — unprivileged clients of the libraries;
  they inherit whatever device access the process is granted.

### Threat Model

The following scenarios represent the primary security concerns for this project
(including auxiliary/support code):

1. **Unsafe memory registration / remote access exposure:** A process using
   `libibverbs` (or pyverbs) registers memory with overly broad access flags or
   publishes `rkey`/MR details to an untrusted peer, allowing remote RDMA read/
   write of application or process memory via the provider datapath.

2. **Malicious or substituted provider plugin:** Compromise or replacement of a
   provider `.so` loaded by `load_driver()` in `libibverbs/dynamic_driver.c`
   (including absolute paths from `RDMAV_DRIVERS`) yields arbitrary code in every
   process that opens an RDMA device.

3. **Privileged device command / DEVX misuse (mlx5):** Incorrect or attacker-
   influenced use of mlx5 DEVX, steering (`dr_*`), or encryption-key object APIs
   in `providers/mlx5` can misconfigure hardware objects, leak key material, or
   divert traffic when the calling process has elevated device capabilities.

4. **ibacm network exposure:** If `server_mode` is set to `open` (or misconfigured
   away from the default Unix-socket mode), `ibacm` accepts TCP clients for path
   resolution while running with administrative privileges, enabling
   unauthorized resolution queries, cache poisoning, or DoS against connection
   setup.

5. **iwpmd / srp_daemon control-plane abuse:** Spoofed or malformed netlink/UDP
   (iwpmd) or MAD/SRP discovery traffic (srp_daemon) can disrupt port mapping or
   storage discovery on hosts where these daemons run privileged.

6. **Work-request / SGE parsing defects in providers:** Bugs in provider WR/SGE
   setup (e.g. length/offset handling in `providers/rxe`, mlx5 WQE builders, or
   similar paths) can cause incorrect DMA bounds, local memory corruption, or
   unexpected device behavior when fed crafted application WRs.

7. **librdmacm preload hijack:** Loading `librdmacm/preload.c` via `LD_PRELOAD`
   in an untrusted environment redirects socket APIs to rsocket/RDMA paths,
   enabling traffic interception or unexpected privilege/network behavior for
   unaware applications.

### Critical Security Assumptions

- The Linux kernel RDMA subsystem and device file permissions correctly enforce
  which processes may open uverbs/umad/rdma_cm devices and which verbs/DEVX
  operations they may perform.
- Hardware IOMMU/MMU and HCA protection domains function correctly; userspace
  cannot bypass them solely through normal verbs posting.
- The provider plugin search path and installed provider packages are
  administered as trusted code; `RDMAV_DRIVERS` is only honored for non-setuid
  processes and is assumed not to point at untrusted binaries in production.
- Calling applications correctly choose MR access flags, QP peer authentication
  (where applicable), and key distribution; the libraries do not implement
  application-level authentication or fabric access control.
- `ibacm` is deployed with `server_mode unix` (or equivalent loopback-only
  binding) unless the deployment intentionally exposes it on a trusted network.
- TLS/application crypto is out of scope for most of the stack; mlx5 crypto APIs
  only program hardware offload objects and assume key material is supplied by a
  trusted caller.
- Diagnostic tools, examples, and tests are not hardened network services and
  must not be exposed as production listeners without additional controls.
