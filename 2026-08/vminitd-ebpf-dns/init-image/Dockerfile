# syntax=docker/dockerfile:1
# Custom vminitd init image, following Apple's container runtime-configuration
# doc ("Use a custom init image"): mirror the stock vminit tag, keep the real
# vminitd as /sbin/vminitd.real, install our dnslink wrapper as /sbin/vminitd.
#
# Build context: init-image/ — must contain the `dnslink` binary (built in the
# preceding workflow step; gitignored here).
#
#   docker build --build-arg VMINIT_VERSION=0.40.1 -t local/custom-init . init-image
ARG VMINIT_VERSION=0.40.1

FROM ghcr.io/apple/containerization/vminit:${VMINIT_VERSION} AS base
FROM ghcr.io/apple/containerization/vminit:${VMINIT_VERSION}
COPY --from=base /sbin/vminitd /sbin/vminitd.real
COPY dnslink /sbin/vminitd