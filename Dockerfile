FROM golang:1.23-alpine AS builder
WORKDIR /src
RUN apk add --no-cache ca-certificates git
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/threat-api ./cmd/api

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=builder /out/threat-api /threat-api
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/threat-api"]
