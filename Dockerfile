FROM golang:1.26.4-bookworm@sha256:d1af0fd434fced72b3b4335440df9d0fd43a4c737ea14aed18b6b3f4e9aab58d AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w \
      -X 'github.com/verophi/verophi/internal/version_info.Version=${VERSION}' \
      -X 'github.com/verophi/verophi/internal/version_info.Commit=${COMMIT}' \
      -X 'github.com/verophi/verophi/internal/version_info.BuildDate=${BUILD_DATE}'" \
    -o /verophi ./cmd/verophi

FROM cgr.dev/chainguard/static:latest@sha256:77d8b8925dc27970ec2f48243f44c7a260d52c49cd778288e4ee97566e0cb75b
COPY --from=builder /verophi /usr/local/bin/verophi
USER 65532:65532
ENTRYPOINT ["verophi"]
