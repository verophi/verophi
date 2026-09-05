# The verophi binary is built ahead of time (goreleaser / make docker: CGO_ENABLED=0,
# static, no -buildmode=pie) and copied in. No build stage, so the image ships the
# exact artifact that is released. TARGETARCH selects the matching prebuilt binary,
# so a single buildx invocation produces a linux/amd64 + linux/arm64 manifest.
FROM cgr.dev/chainguard/static:latest@sha256:f51c2493951313c3ad4069080b2814ffb6ed6fe3909dabeb84a9482f42d5600b
ARG TARGETARCH
COPY verophi-${TARGETARCH} /usr/local/bin/verophi
USER 65532:65532
ENTRYPOINT ["verophi"]
