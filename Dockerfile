ARG GO_VERSION=1.25

FROM golang:${GO_VERSION}-bookworm AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/kubeapt ./cmd/kubeapt/

FROM gcr.io/distroless/static-debian12

COPY --from=builder /out/kubeapt /usr/local/bin/kubeapt
ENTRYPOINT ["/usr/local/bin/kubeapt"]
