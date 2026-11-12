# syntax=docker/dockerfile:1
FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/tempfile-go .

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/tempfile-go /app/tempfile-go
USER nonroot:nonroot
ENV LISTEN_ADDR=:8080 DATA_DIR=/data REQUIRE_DELETE_TOKEN=true
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/app/tempfile-go"]
