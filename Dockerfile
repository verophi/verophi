# The verophi binary is built ahead of time (goreleaser / make docker: CGO_ENABLED=0,
# static, no -buildmode=pie) and copied in. No build stage, so the image ships the
# exact artifact that is released. TARGETARCH selects the matching prebuilt binary,
# so a single buildx invocation produces a linux/amd64 + linux/arm64 manifest.
FROM cgr.dev/chainguard/static:latest@sha256:8658e9eaeb2294fa0e49b0667f7d66b4e21fa7690b8d2a4c30cd1d013ceb9eb7
ARG TARGETARCH
COPY verophi-${TARGETARCH} /usr/local/bin/verophi
USER 65532:65532
ENTRYPOINT ["verophi"]
