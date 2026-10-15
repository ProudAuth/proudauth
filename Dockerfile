# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Reproducible, pinned build (DEP-003). The runtime image contains only the static
# binaries and CA roots, runs as a non-root user and works with a read-only root
# filesystem (DEP-004).
FROM --platform=$BUILDPLATFORM golang:1.27.2-trixie@sha256:e58d6f83b3416618d8bcac2b3dde1b7f7e3c4a77d25e88637f8bbae81536c48d AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-s -w -buildid= -X main.version=${VERSION}" -o /out/identity-server ./cmd/identity-server && \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-s -w -buildid= -X main.version=${VERSION}" -o /out/identity-worker ./cmd/identity-worker && \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-s -w -buildid= -X main.version=${VERSION}" -o /out/identity-cli ./cmd/identity-cli

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG VERSION=dev
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="ProudAuth" \
      org.opencontainers.image.description="Self-hosted identity API and background worker" \
      org.opencontainers.image.source="https://github.com/proudauth/proudauth" \
      org.opencontainers.image.url="https://proudauth.com" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"
COPY --from=build /out/ /usr/local/bin/
COPY LICENSE NOTICE /usr/share/doc/proudauth/
USER 65532:65532
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/identity-server"]
