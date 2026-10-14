# The verophi binary is built ahead of time (goreleaser / make docker: CGO_ENABLED=0,
# static, no -buildmode=pie) and copied in. No build stage, so the image ships the
# exact artifact that is released. TARGETARCH selects the matching prebuilt binary,
# so a single buildx invocation produces a linux/amd64 + linux/arm64 manifest.
FROM cgr.dev/chainguard/static:latest@sha256:fe55470f22d3259488d9d3739168d8f04da67755f0b69382bc26eda4a7d3d327
ARG TARGETARCH
COPY verophi-${TARGETARCH} /usr/local/bin/verophi
USER 65532:65532
ENTRYPOINT ["verophi"]
