# Builds any of the three binaries into a minimal image:
#   docker build -f deploy/docker/Dockerfile --build-arg CMD=sm-agent -t registry.internal/sm-agent:0.1.0 .
#   docker build -f deploy/docker/Dockerfile --build-arg CMD=smd      -t registry.internal/smd:0.1.0 .
#
# Mirror golang:1.27 into your own registry and set GO_IMAGE to it; nothing is
# pulled from outside at runtime (the final image is FROM scratch).
ARG GO_IMAGE=golang:1.27
FROM ${GO_IMAGE} AS build
ARG CMD
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN test -n "$CMD" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/${CMD}

FROM scratch
COPY --from=build /out/app /app
USER 10001:10001
ENTRYPOINT ["/app"]
