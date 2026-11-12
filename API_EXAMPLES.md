# API examples

## Upload local file

```bash
curl -X POST http://localhost:8080/api/upload/local \
  -F 'files=@document.pdf' \
  -F 'expiryHours=24'
```

The response includes `deleteToken`; keep it if you want to delete the file early.

## Get file info / security info

```bash
curl http://localhost:8080/api/file/<fileId>
curl http://localhost:8080/api/file/<fileId>/security
```

## Download / preview

```bash
curl -L http://localhost:8080/<fileId>/download -o file.bin
# preview only supports raster images
curl http://localhost:8080/<fileId>/preview
```

## Delete

```bash
curl -X DELETE http://localhost:8080/api/file/<fileId> \
  -H 'X-Delete-Token: <deleteToken>'
```

## Import from URL

Only public HTTP(S) destinations are allowed, and ports default to 80/443.

```bash
curl -X POST http://localhost:8080/api/upload/url \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com/file.pdf","customName":"file.pdf","expiryHours":6}'
```

## Create folder

```bash
curl -X POST http://localhost:8080/api/folder \
  -H 'Content-Type: application/json' \
  -d '{"expiryHours":24,"title":"Project files"}'
```

The response contains a one-time `manageToken`.

## Upload into folder

```bash
curl -X POST http://localhost:8080/api/upload/local \
  -H 'X-Folder-Id: <folderId>' \
  -H 'X-Folder-Token: <manageToken>' \
  -F 'files=@a.pdf' \
  -F 'files=@b.png'
```

You may also send `folderId` and `folderToken` as multipart form fields.

## Folder operations

```bash
curl http://localhost:8080/api/folder/<folderId>
curl -L http://localhost:8080/<folderId>/download -o files.zip
curl -X PATCH http://localhost:8080/api/folder/<folderId> \
  -H 'X-Folder-Token: <manageToken>' \
  -H 'Content-Type: application/json' \
  -d '{"title":"Renamed"}'
curl -X DELETE http://localhost:8080/api/folder/<folderId> \
  -H 'X-Folder-Token: <manageToken>'
```
