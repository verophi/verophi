# The verophi binary is built ahead of time (goreleaser / make docker: CGO_ENABLED=0,
# static, no -buildmode=pie) and copied in. No build stage, so the image ships the
# exact artifact that is released. TARGETARCH selects the matching prebuilt binary,
# so a single buildx invocation produces a linux/amd64 + linux/arm64 manifest.
FROM cgr.dev/chainguard/static:latest@sha256:60582b2ae6074f641094af0f370d4ab241aab271858a66223dcde7eee9f51638
ARG TARGETARCH
COPY verophi-${TARGETARCH} /usr/local/bin/verophi
USER 65532:65532
ENTRYPOINT ["verophi"]
