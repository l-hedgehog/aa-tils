# vminitd-ebpf-dns

Custom `vminitd` init image that installs DNS-redirection eBPF hooks at VM
boot, then hands off to the stock Apple `vminitd`.

Pushed by CI to **`ghcr.io/l-hedgehog/aa-tils/vminitd-ebpf-dns:<tag>`**, where
`<tag>` defaults to the short commit SHA that triggered the build (public
GHCR package).

## How it works

The `container` VM boots the custom init image instead of the
stock one. PID 1 is our `dnslink` wrapper:

1. mount procfs, read `/proc/cmdline` for `dnslink.gateway=<ip>` (the
   upstream DNS server) and optional `dnslink.port=<port>` (default
   upstream `1.1.1.1:53`);
2. mount cgroup2 at `/mnt`, load the embedded `dns_sockaddr.bpf.o` and attach
   its 3 hooks (`cgroup/connect4`, `cgroup/sendmsg4`,
   `cgroup/recvmsg4`) to the root cgroup — so **all descendant container
   cgroups** inherit the redirect;
3. `exec` the real init as `/sbin/vminitd.real`, replaying our argv.

Every DNS query that nameserver-aware apps send to e.g. `127.0.8.6:53` is
transparently redirected to the configured upstream `<ip>:<port>` (default
`1.1.1.1:53`).
The `recvmsg4` hook rewrites the reported source back so resolvers that
verify the peer (musl `getent`) see the requested nameserver.

Config reference (`container run --kernel-arg ...`):

| arg                    | effect                                   | default   |
|------------------------|------------------------------------------|-----------|
| `dnslink.gateway=<ip>` | upstream DNS server = `<ip>:53`          | `1.1.1.1` |
| `dnslink.port=<port>`  | override the upstream port               | `53`      |

`dnslink.gateway` is the **upstream DNS server** queries are redirected to
(despite the name, it is not a network gateway). With the defaults, the
upstream is `1.1.1.1:53`.

## Layout

```
vmlinux.h/                  git submodule (https://github.com/libbpf/vmlinux.h.git,
                            pinned to 679a3da9a3e4123788fae6f658d9841615f71046)
ebpf/                       dns_sockaddr.bpf.c + headers + Makefile
dnslink/                    zero-dependency Rust loader/wrapper (aarch64-musl static)
init-image/Dockerfile       Apple-doc pattern ("Use a custom init image")
.github/workflows/vminitd-ebpf-dns.yml  native-arm64 CI: build eBPF -> dnslink -> init image -> push GHCR
```

## Design decisions

- **eBPF**: built from source with the **system** `libbpf-dev` (no vendored
  headers) + pinned `vmlinux.h` submodule; the Makefile builds exactly the one
  object dnslink embeds.
- **dnslink**: static `aarch64-unknown-linux-musl`, hand-rolled syscalls,
  zero external crates — `cargo build` works fully offline.
- **init image**: built with the Apple runtime-configuration Dockerfile
  pattern: `FROM vminit:<scVersion>`, keep the real init as
  `/sbin/vminitd.real`, `COPY` the dnslink binary as `/sbin/vminitd`. The base
  `vminit` tag auto-follows apple/container's `scVersion` (current `0.41.0`).
- **CI**: `ubuntu-24.04-arm` (native arm64, no Docker-in-Docker, no buildx),
  deps installed in the runner, image assembly is the only `docker build`.

## Build locally

```bash
# 1. eBPF object (depends on clang + libbpf headers; see ebpf/Makefile header)
make -C ebpf

# 2. embed it into dnslink, build the static binary
cp ebpf/dns_sockaddr.bpf.o dnslink/
rustup target add aarch64-unknown-linux-musl
sudo apt-get install -y musl-tools
cd dnslink && cargo build --release --target aarch64-unknown-linux-musl && cd ..

# 3. assemble the custom init image
cp dnslink/target/aarch64-unknown-linux-musl/release/dnslink init-image/dnslink
docker build --build-arg VMINIT_VERSION=0.40.1 -t local/custom-init:latest init-image
```

Then run (container CLI, this repo's setup):

```bash
container run -w /app --network ebpf-net \
  --init-image local/custom-init:latest \
  --kernel-arg dnslink.gateway=192.168.254.1 \
  --dns 127.0.8.6 \
  nicolaka/netshoot sh -c 'getent hosts example.com'
```

Device log should show `Run /sbin/vminitd` then
`dnslink: upstream from /proc/cmdline: 192.168.254.1:53` and
`attached 3 cgroup hook(s) at /mnt`.

## CI / publishing

`.github/workflows/vminitd-ebpf-dns.yml` (repo root, native arm64 runner; path-scoped
to this project so it only runs on changes here):

1. checkout incl. the pinned `vmlinux.h` submodule
2. `apt-get install clang libbpf-dev linux-libc-dev musl-tools`; `rustup` via
   `dtolnay/rust-toolchain` (adds `aarch64-unknown-linux-musl`)
3. `make -C ebpf` -> `dns_sockaddr.bpf.o`
4. `cp ebpf/dns_sockaddr.bpf.o dnslink/`
5. `cargo build --release --target aarch64-unknown-linux-musl` (offline)
6. `docker build` the init image (Apple pattern)
7. `docker push ghcr.io/l-hedgehog/aa-tils/vminitd-ebpf-dns:<tag>` using
   `secrets.GITHUB_TOKEN` (no PAT)

Triggers: `push` to `main` (path-scoped to this folder) and `workflow_dispatch`
(two optional inputs):

| input             | default when empty                       |
|-------------------|------------------------------------------|
| `vminit-version`  | auto-follow apple/container `scVersion`  |
| `tag`             | short commit SHA of the triggering run   |