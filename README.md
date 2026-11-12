# tempfile-go

A security-hardened temporary file hosting service implemented in Go 1.22+ with only the standard library.

## Features

- `POST /api/upload/local` - multipart upload, up to 20 files/request
- `POST /api/upload/url` - fetch a public HTTP(S) URL with SSRF protection
- `GET /api/file/{fileId}` - metadata
- `GET /api/file/{fileId}/security` - security analysis
- `DELETE /api/file/{fileId}` - delete file (delete token required by default)
- `GET /{fileId}/download` - forced attachment download
- `GET /{fileId}/preview` - image-only preview
- Folder APIs compatible with the reference shape
- `GET /{folderId}/download` - streamed ZIP download
- Automatic expiry deletion (1-48 hours)
- On-disk metadata persistence across restarts
- SHA-256 hashing
- MIME sniffing + extension consistency checks
- Dangerous extension / executable magic rejection
- ZIP entry scan and zip-bomb limits
- Rate limiting
- Security headers
- No uploaded file is ever executed by the service

## Quick start

```bash
go run .
# listen on :8080 by default
```

Upload:

```bash
curl -X POST http://localhost:8080/api/upload/local \
  -F 'files=@document.pdf' \
  -F 'expiryHours=24'
```

Download:

```bash
curl -L http://localhost:8080/<fileId>/download -o document.pdf
```

Delete (secure default):

```bash
curl -X DELETE http://localhost:8080/api/file/<fileId> \
  -H 'X-Delete-Token: <deleteToken>'
```

## Important environment variables

| Variable | Default | Meaning |
|---|---:|---|
| `LISTEN_ADDR` | `:8080` | HTTP listen address |
| `DATA_DIR` | `./data` | Storage root |
| `PUBLIC_BASE_URL` | inferred from request | Public URL prefix |
| `MAX_FILE_SIZE` | `104857600` | 100 MiB per file |
| `MAX_FILES_PER_REQUEST` | `20` | multipart file count |
| `REQUIRE_DELETE_TOKEN` | `true` | protect DELETE endpoint |
| `TRUST_PROXY` | `false` | trust X-Forwarded-For only behind a trusted proxy |
| `URL_IMPORT_PORTS` | `80,443` | allowed remote ports for URL import |
| `CLEANUP_INTERVAL` | `1m` | expired file/folder sweep interval |
| `CLAMAV_ADDR` | empty | optional clamd TCP address, e.g. `clamav:3310` |
| `CLAMAV_FAIL_OPEN` | `false` | if ClamAV is configured but unavailable, reject uploads by default |

## Security notes

1. Uploaded bytes are written to a random internal object path, never a user-controlled path.
2. Downloads always use `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`.
3. HTML, SVG, JS, shell scripts, native executables, installers and other active content are rejected by default.
4. ZIP archives are inspected before acceptance. Entries with traversal names, dangerous extensions, excessive entry count, excessive uncompressed size or suspicious compression ratios are rejected.
5. URL import rejects localhost, RFC1918/private, link-local, multicast, unspecified and other non-public destinations. DNS is checked before and during connection, including redirects.
6. The service never calls shell commands and never opens uploaded files as executables.
7. Set `CLAMAV_ADDR` in production if you want real antivirus scanning in addition to built-in static checks. The service uses clamd INSTREAM and never executes the file.
8. For Internet deployment, put the service behind TLS (Caddy/nginx/load balancer), isolate the storage volume, run as a non-root user, and consider ClamAV/object-storage malware scanning for a second layer.

## Production recommendations

- Run in a container with a read-only root filesystem and a dedicated writable `/data` volume.
- Set CPU/memory/pid limits.
- Do not mount Docker socket or sensitive host paths.
- Use a separate domain for file downloads if browsers will access untrusted files.
- Keep `REQUIRE_DELETE_TOKEN=true` unless exact backward compatibility is more important than delete authorization.
