package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type App struct {
	cfg             Config
	store           *Store
	uploadLimiter   *FixedWindowLimiter
	downloadLimiter *FixedWindowLimiter
	globalLimiter   *FixedWindowLimiter
	urlClient       *http.Client
}

func main() {
	cfg := loadConfig()
	store, err := NewStore(cfg.DataDir)
	if err != nil {
		log.Fatal(err)
	}
	app := &App{cfg: cfg, store: store, uploadLimiter: NewLimiter(time.Hour, 200), downloadLimiter: NewLimiter(15*time.Minute, 5000), globalLimiter: NewLimiter(15*time.Minute, 10000), urlClient: buildSafeHTTPClient(cfg)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", app.index)
	mux.HandleFunc("GET /{id}/", app.handlePublicPage)
	mux.HandleFunc("POST /api/upload/local", app.handleUploadLocal)
	mux.HandleFunc("POST /api/upload/url", app.handleUploadURL)
	mux.HandleFunc("GET /api/file/{id}", app.handleFileInfo)
	mux.HandleFunc("GET /api/file/{id}/security", app.handleSecurity)
	mux.HandleFunc("DELETE /api/file/{id}", app.handleDeleteFile)
	mux.HandleFunc("GET /{id}/download", app.handleDownload)
	mux.HandleFunc("GET /{id}/preview", app.handlePreview)
	mux.HandleFunc("POST /api/folder", app.handleCreateFolder)
	mux.HandleFunc("GET /api/folder/{id}", app.handleGetFolder)
	mux.HandleFunc("GET /api/folder/{id}/files", app.handleGetFolder)
	mux.HandleFunc("PATCH /api/folder/{id}", app.handleRenameFolder)
	mux.HandleFunc("DELETE /api/folder/{id}/files/{fileId}", app.handleDeleteFolderFile)
	mux.HandleFunc("DELETE /api/folder/{id}", app.handleDeleteFolder)
	srv := &http.Server{Addr: cfg.ListenAddr, Handler: app.securityMiddleware(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 5 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	go app.cleanupLoop()
	log.Printf("tempfile-go listening on %s, data=%s", cfg.ListenAddr, cfg.DataDir)
	log.Fatal(srv.ListenAndServe())
}

func (a *App) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("X-Frame-Options", "DENY")
		ip := clientIP(r, a.cfg.TrustProxy)
		ok, rem, reset := a.globalLimiter.Allow(ip)
		w.Header().Set("X-GlobalRateLimit-Remaining", strconv.Itoa(rem))
		if !ok {
			w.Header().Set("Retry-After", strconv.Itoa(max(1, int(time.Until(reset).Seconds()))))
			writeErr(w, 429, "global rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) rateUpload(w http.ResponseWriter, r *http.Request) bool {
	ip := clientIP(r, a.cfg.TrustProxy)
	ok, rem, reset := a.uploadLimiter.Allow(ip)
	w.Header().Set("X-RateLimit-Limit", "200")
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(rem))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
	if !ok {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(time.Until(reset).Seconds()))))
		writeErr(w, 429, "upload rate limit exceeded")
		return false
	}
	return true
}
func (a *App) rateDownload(w http.ResponseWriter, r *http.Request) bool {
	ip := clientIP(r, a.cfg.TrustProxy)
	ok, _, reset := a.downloadLimiter.Allow(ip)
	if !ok {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(time.Until(reset).Seconds()))))
		writeErr(w, 429, "download rate limit exceeded")
		return false
	}
	return true
}

func (a *App) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "tempfile-go API\n")
}

func (a *App) handlePublicPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if validID(id, 11) {
		rec, ok := a.store.GetFile(id)
		if !ok || !rec.ExpiryTime.After(time.Now()) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><title>Temporary file</title><style>body{font-family:system-ui;max-width:720px;margin:48px auto;padding:0 20px}code{word-break:break-all}</style><h1>Temporary file</h1><p>Name: <code>%s</code></p><p>Size: %d bytes</p><p>Expires: %s</p><p><a href=\"/%s/download\">Download</a></p>", htmlEscape(rec.Name), rec.Size, rec.ExpiryTime.Format(time.RFC3339), rec.ID)
		return
	}
	if validID(id, 12) {
		f, ok := a.store.GetFolder(id)
		if !ok || !f.ExpiryTime.After(time.Now()) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		a.handleGetFolder(w, r)
		return
	}
	http.NotFound(w, r)
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

func (a *App) handleUploadLocal(w http.ResponseWriter, r *http.Request) {
	if !a.rateUpload(w, r) {
		return
	}
	// total request cap: file limits + multipart overhead
	r.Body = http.MaxBytesReader(w, r.Body, a.cfg.MaxFileSize*int64(a.cfg.MaxFilesPerRequest)+8*1024*1024)
	mr, err := r.MultipartReader()
	if err != nil {
		writeErr(w, 400, "invalid multipart/form-data")
		return
	}
	expiry := time.Hour
	folderID := firstNonEmpty(r.Header.Get("X-Folder-Id"), "")
	folderToken := firstNonEmpty(r.Header.Get("X-Folder-Token"), "")
	positions := parsePositions(r.Header.Get("X-Folder-Positions"))
	type pending struct {
		tmp, name   string
		size        int64
		scan        ScanResult
		pos         int
		deleteToken string
	}
	var files []pending
	defer func() {
		for _, p := range files {
			_ = os.Remove(p.tmp)
		}
	}()
	formExpiry := ""
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			writeErr(w, 400, "malformed multipart body")
			return
		}
		if part.FileName() == "" {
			b, _ := io.ReadAll(io.LimitReader(part, 4096))
			v := strings.TrimSpace(string(b))
			switch part.FormName() {
			case "expiryHours":
				formExpiry = v
			case "folderId":
				if folderID == "" {
					folderID = v
				}
			case "folderToken":
				if folderToken == "" {
					folderToken = v
				}
			case "folderPositions":
				if len(positions) == 0 {
					positions = parsePositions(v)
				}
			}
			part.Close()
			continue
		}
		if part.FormName() != "files" && !strings.HasPrefix(part.FormName(), "files[") {
			part.Close()
			writeErr(w, 400, "file field must be named files")
			return
		}
		if len(files) >= a.cfg.MaxFilesPerRequest {
			part.Close()
			writeErr(w, 400, "too many files")
			return
		}
		name := cleanFilename(part.FileName())
		tmp, sz, hash, err := a.receiveToTemp(part, a.cfg.MaxFileSize)
		part.Close()
		if err != nil {
			writeErr(w, statusFromUploadErr(err), err.Error())
			return
		}
		scan, err := scanFile(tmp, name, a.cfg)
		if err != nil {
			_ = os.Remove(tmp)
			writeErr(w, 400, "file rejected: "+err.Error(), "UNSAFE_FILE")
			return
		}
		if a.cfg.ClamAVAddr != "" {
			if err := scanWithClamAV(tmp, a.cfg.ClamAVAddr); err != nil {
				_ = os.Remove(tmp)
				if a.cfg.ClamAVFailOpen && strings.Contains(err.Error(), "unavailable") {
					log.Printf("clamav fail-open: %v", err)
				} else {
					writeErr(w, 400, "file rejected: "+err.Error(), "MALWARE_SCAN_FAILED")
					return
				}
			}
		}
		scan.Patterns = append(scan.Patterns, "sha256:"+hash)
		pos := len(files)
		if pos < len(positions) {
			pos = positions[pos]
		}
		files = append(files, pending{tmp: tmp, name: name, size: sz, scan: scan, pos: pos, deleteToken: randomToken()})
	}
	if len(files) == 0 {
		writeErr(w, 400, "no files uploaded")
		return
	}
	if folderID != "" {
		f, ok := a.store.GetFolder(folderID)
		if !ok || !f.ExpiryTime.After(time.Now()) {
			writeErr(w, 404, "folder not found or expired", "FOLDER_NOT_FOUND")
			return
		}
		if !tokenEqual(f.ManageTokenHash, folderToken) {
			writeErr(w, 403, "folder token missing or wrong", "FOLDER_FORBIDDEN")
			return
		}
		expiry = time.Until(f.ExpiryTime)
	}
	if folderID == "" {
		var err error
		expiry, err = parseExpiry(formExpiry)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
	}
	if folderID != "" {
		count, _ := a.store.FolderStats(folderID)
		if count+len(files) > 50 {
			writeErr(w, 400, "folder is full", "FOLDER_FULL")
			return
		}
	}
	now := time.Now()
	exp := now.Add(expiry)
	if folderID != "" {
		f, _ := a.store.GetFolder(folderID)
		exp = f.ExpiryTime
	}
	out := []map[string]any{}
	for _, p := range files {
		id := randomID(11)
		stored := id + ".bin"
		dest := a.store.ObjectPath(stored)
		if err := os.Rename(p.tmp, dest); err != nil {
			writeErr(w, 500, "failed to store file")
			return
		}
		_ = os.Chmod(dest, 0600)
		sha := strings.TrimPrefix(lastPrefix(p.scan.Patterns, "sha256:"), "sha256:")
		p.scan.Patterns = withoutPrefix(p.scan.Patterns, "sha256:")
		rec := &FileRecord{ID: id, Name: p.name, Size: p.size, MimeType: p.scan.MimeType, SHA256: sha, UploadType: "local", UploadTime: now, ExpiryTime: exp, ClientIP: maskIP(clientIP(r, a.cfg.TrustProxy)), StoredName: stored, DeleteTokenHash: hashToken(p.deleteToken), FolderID: folderID, Position: p.pos, HasWarning: p.scan.HasWarning, RiskLevel: p.scan.RiskLevel, SuspiciousPatterns: p.scan.Patterns, Recommendations: p.scan.Recommendations}
		if err := a.store.PutFile(rec); err != nil {
			_ = os.Remove(dest)
			writeErr(w, 500, "failed to persist metadata")
			return
		}
		item := a.publicFile(r, rec)
		item["deleteToken"] = p.deleteToken
		out = append(out, item)
	}
	resp := map[string]any{"success": true, "files": out, "message": fmt.Sprintf("%d file(s) uploaded successfully", len(out))}
	if folderID != "" {
		f, _ := a.store.GetFolder(folderID)
		resp["folder"] = a.publicFolder(r, f, false)
	}
	writeJSON(w, 200, resp)
}

func (a *App) handleUploadURL(w http.ResponseWriter, r *http.Request) {
	if !a.rateUpload(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var body struct {
		URL         string `json:"url"`
		CustomName  string `json:"customName"`
		ExpiryHours int    `json:"expiryHours"`
		FolderID    string `json:"folderId"`
		FolderToken string `json:"folderToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	u, err := url.Parse(body.URL)
	if err != nil || validateImportURL(u, a.cfg) != nil {
		writeErr(w, 400, "unsafe or invalid source URL")
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, u.String(), nil)
	if err != nil {
		writeErr(w, 400, "invalid source URL")
		return
	}
	req.Header.Set("User-Agent", "tempfile-go/1.0")
	res, err := a.urlClient.Do(req)
	if err != nil {
		writeErr(w, 400, "failed to fetch source URL: "+err.Error())
		return
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		writeErr(w, 400, fmt.Sprintf("source returned HTTP %d", res.StatusCode))
		return
	}
	if res.ContentLength > a.cfg.MaxFileSize {
		writeErr(w, 413, "remote file too large")
		return
	}
	name := cleanFilename(body.CustomName)
	if body.CustomName == "" {
		name = cleanFilename(filepath.Base(res.Request.URL.Path))
		if name == "file" {
			name = "download"
		}
	}
	if filepath.Ext(name) == "" {
		if ext, _ := mime.ExtensionsByType(strings.Split(res.Header.Get("Content-Type"), ";")[0]); len(ext) > 0 {
			name += ext[0]
		}
	}
	tmp, sz, hash, err := a.receiveToTemp(res.Body, a.cfg.MaxFileSize)
	if err != nil {
		writeErr(w, statusFromUploadErr(err), err.Error())
		return
	}
	defer os.Remove(tmp)
	scan, err := scanFile(tmp, name, a.cfg)
	if err != nil {
		writeErr(w, 400, "file rejected: "+err.Error(), "UNSAFE_FILE")
		return
	}
	if a.cfg.ClamAVAddr != "" {
		if err := scanWithClamAV(tmp, a.cfg.ClamAVAddr); err != nil {
			if a.cfg.ClamAVFailOpen && strings.Contains(err.Error(), "unavailable") {
				log.Printf("clamav fail-open: %v", err)
			} else {
				writeErr(w, 400, "file rejected: "+err.Error(), "MALWARE_SCAN_FAILED")
				return
			}
		}
	}
	expiryStr := strconv.Itoa(body.ExpiryHours)
	if body.ExpiryHours == 0 {
		expiryStr = "1"
	}
	dur, err := parseExpiry(expiryStr)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	folderID := firstNonEmpty(r.Header.Get("X-Folder-Id"), body.FolderID)
	folderToken := firstNonEmpty(r.Header.Get("X-Folder-Token"), body.FolderToken)
	exp := time.Now().Add(dur)
	if folderID != "" {
		f, ok := a.store.GetFolder(folderID)
		if !ok || !f.ExpiryTime.After(time.Now()) {
			writeErr(w, 404, "folder not found or expired", "FOLDER_NOT_FOUND")
			return
		}
		if !tokenEqual(f.ManageTokenHash, folderToken) {
			writeErr(w, 403, "folder token missing or wrong", "FOLDER_FORBIDDEN")
			return
		}
		count, _ := a.store.FolderStats(folderID)
		if count >= 50 {
			writeErr(w, 400, "folder is full", "FOLDER_FULL")
			return
		}
		exp = f.ExpiryTime
	}
	id := randomID(11)
	stored := id + ".bin"
	dest := a.store.ObjectPath(stored)
	if err = os.Rename(tmp, dest); err != nil {
		writeErr(w, 500, "failed to store file")
		return
	}
	_ = os.Chmod(dest, 0600)
	del := randomToken()
	rec := &FileRecord{ID: id, Name: name, Size: sz, MimeType: scan.MimeType, SHA256: hash, UploadType: "url", UploadTime: time.Now(), ExpiryTime: exp, ClientIP: maskIP(clientIP(r, a.cfg.TrustProxy)), StoredName: stored, DeleteTokenHash: hashToken(del), FolderID: folderID, HasWarning: scan.HasWarning, RiskLevel: scan.RiskLevel, SuspiciousPatterns: scan.Patterns, Recommendations: scan.Recommendations}
	if err = a.store.PutFile(rec); err != nil {
		_ = os.Remove(dest)
		writeErr(w, 500, "failed to persist metadata")
		return
	}
	item := a.publicFile(r, rec)
	item["deleteToken"] = del
	writeJSON(w, 200, map[string]any{"success": true, "file": item})
}

func (a *App) receiveToTemp(src io.Reader, limit int64) (string, int64, string, error) {
	tmp, err := os.CreateTemp(a.store.root, "incoming-*.part")
	if err != nil {
		return "", 0, "", err
	}
	name := tmp.Name()
	defer func() { _ = tmp.Close() }()
	h := sha256.New()
	lr := io.LimitReader(src, limit+1)
	n, err := io.Copy(io.MultiWriter(tmp, h), lr)
	if err != nil {
		_ = os.Remove(name)
		return "", 0, "", err
	}
	if n > limit {
		_ = os.Remove(name)
		return "", 0, "", fmt.Errorf("file too large (max %d bytes)", limit)
	}
	if err := tmp.Sync(); err != nil {
		_ = os.Remove(name)
		return "", 0, "", err
	}
	return name, n, hex.EncodeToString(h.Sum(nil)), nil
}

func (a *App) handleFileInfo(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(id, 11) {
		writeErr(w, 404, "file not found or expired")
		return
	}
	rec, ok := a.store.GetFile(id)
	if !ok || !rec.ExpiryTime.After(time.Now()) {
		writeErr(w, 404, "file not found or expired")
		return
	}
	m := a.publicFileInfo(r, rec)
	writeJSON(w, 200, map[string]any{"success": true, "file": m})
}
func (a *App) handleSecurity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rec, ok := a.store.GetFile(id)
	if !ok || !rec.ExpiryTime.After(time.Now()) {
		writeErr(w, 404, "file not found or expired")
		return
	}
	writeJSON(w, 200, map[string]any{"success": true, "security": map[string]any{"fileId": rec.ID, "fileName": rec.Name, "mimeType": rec.MimeType, "hasWarning": rec.HasWarning, "suspiciousPatterns": rec.SuspiciousPatterns, "hash": rec.SHA256, "size": rec.Size, "uploadType": rec.UploadType, "uploadTime": rec.UploadTime.UnixMilli(), "clientIP": rec.ClientIP, "riskLevel": rec.RiskLevel, "recommendations": rec.Recommendations}})
}
func (a *App) handleDeleteFile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rec, ok := a.store.GetFile(id)
	if !ok {
		writeErr(w, 404, "file not found or expired")
		return
	}
	if rec.FolderID != "" {
		f, fok := a.store.GetFolder(rec.FolderID)
		if !fok || !tokenEqual(f.ManageTokenHash, folderToken(r)) {
			writeErr(w, 403, "file belongs to a folder; folder token required", "FOLDER_TOKEN_REQUIRED")
			return
		}
	} else if a.cfg.RequireDeleteToken && !tokenEqual(rec.DeleteTokenHash, deleteToken(r)) {
		writeErr(w, 403, "delete token required")
		return
	}
	if err := a.store.DeleteFile(id); err != nil {
		writeErr(w, 500, "delete failed")
		return
	}
	writeJSON(w, 200, map[string]any{"success": true, "message": "File deleted successfully"})
}

func (a *App) handleDownload(w http.ResponseWriter, r *http.Request) {
	if !a.rateDownload(w, r) {
		return
	}
	id := r.PathValue("id")
	if validID(id, 12) {
		a.handleFolderDownload(w, r, id)
		return
	}
	rec, ok := a.store.GetFile(id)
	if !ok || !rec.ExpiryTime.After(time.Now()) {
		writeErr(w, 404, "file not found or expired")
		return
	}
	f, err := os.Open(a.store.ObjectPath(rec.StoredName))
	if err != nil {
		writeErr(w, 404, "file not found or expired")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", rec.MimeType)
	w.Header().Set("Content-Length", strconv.FormatInt(rec.Size, 10))
	w.Header().Set("Content-Disposition", `attachment; filename*=UTF-8''`+url.PathEscape(rec.Name))
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	_, _ = io.Copy(w, f)
}
func (a *App) handlePreview(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rec, ok := a.store.GetFile(id)
	if !ok || !rec.ExpiryTime.After(time.Now()) {
		http.NotFound(w, r)
		return
	}
	allowed := rec.MimeType == "image/jpeg" || rec.MimeType == "image/png" || rec.MimeType == "image/gif" || rec.MimeType == "image/webp"
	if !allowed {
		writeErr(w, 400, "preview is only available for safe raster images")
		return
	}
	f, err := os.Open(a.store.ObjectPath(rec.StoredName))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", rec.MimeType)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Cache-Control", "private, max-age=300")
	_, _ = io.Copy(w, f)
}

func (a *App) handleCreateFolder(w http.ResponseWriter, r *http.Request) {
	if !a.rateUpload(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
	var b struct {
		ExpiryHours int    `json:"expiryHours"`
		Title       string `json:"title"`
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	if b.ExpiryHours == 0 {
		b.ExpiryHours = 1
	}
	if b.ExpiryHours < 1 || b.ExpiryHours > 48 {
		writeErr(w, 400, "expiryHours must be between 1 and 48 for folders")
		return
	}
	d := time.Duration(b.ExpiryHours) * time.Hour
	title := strings.TrimSpace(b.Title)
	rr := []rune(title)
	if len(rr) > 80 {
		title = string(rr[:80])
	}
	token := randomToken()
	f := &FolderRecord{ID: randomID(12), Title: title, CreatedAt: time.Now(), ExpiryTime: time.Now().Add(d), ManageTokenHash: hashToken(token)}
	if err := a.store.PutFolder(f); err != nil {
		writeErr(w, 500, "failed to create folder")
		return
	}
	m := a.publicFolder(r, f, true)
	m["manageToken"] = token
	writeJSON(w, 200, map[string]any{"success": true, "folder": m})
}
func (a *App) handleGetFolder(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	f, ok := a.store.GetFolder(id)
	if !ok || !f.ExpiryTime.After(time.Now()) {
		writeErr(w, 404, "folder not found or expired")
		return
	}
	files := []map[string]any{}
	for _, rec := range a.store.FilesInFolder(id) {
		m := a.publicFile(r, rec)
		m["mimeType"] = rec.MimeType
		m["position"] = rec.Position
		m["hasWarning"] = rec.HasWarning
		m["downloadUrl"] = a.baseURL(r) + "/" + rec.ID + "/download"
		files = append(files, m)
	}
	writeJSON(w, 200, map[string]any{"success": true, "folder": a.publicFolder(r, f, false), "files": files})
}
func (a *App) handleRenameFolder(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	f, ok := a.store.GetFolder(id)
	if !ok {
		writeErr(w, 404, "folder not found")
		return
	}
	if !tokenEqual(f.ManageTokenHash, folderToken(r)) {
		writeErr(w, 403, "folder token missing or wrong")
		return
	}
	var b struct {
		Title string `json:"title"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 8*1024)).Decode(&b) != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	title := strings.TrimSpace(b.Title)
	rr := []rune(title)
	if len(rr) > 80 {
		title = string(rr[:80])
	}
	if err := a.store.RenameFolder(id, title); err != nil {
		writeErr(w, 500, "rename failed")
		return
	}
	writeJSON(w, 200, map[string]any{"success": true, "message": "Folder renamed successfully"})
}
func (a *App) handleDeleteFolderFile(w http.ResponseWriter, r *http.Request) {
	id, fid := r.PathValue("id"), r.PathValue("fileId")
	f, ok := a.store.GetFolder(id)
	if !ok {
		writeErr(w, 404, "folder not found")
		return
	}
	if !tokenEqual(f.ManageTokenHash, folderToken(r)) {
		writeErr(w, 403, "folder token missing or wrong")
		return
	}
	rec, ok := a.store.GetFile(fid)
	if !ok || rec.FolderID != id {
		writeErr(w, 404, "file not found in folder")
		return
	}
	if err := a.store.DeleteFile(fid); err != nil {
		writeErr(w, 500, "delete failed")
		return
	}
	writeJSON(w, 200, map[string]any{"success": true, "message": "File deleted successfully"})
}
func (a *App) handleDeleteFolder(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	f, ok := a.store.GetFolder(id)
	if !ok {
		writeErr(w, 404, "folder not found")
		return
	}
	if !tokenEqual(f.ManageTokenHash, folderToken(r)) {
		writeErr(w, 403, "folder token missing or wrong")
		return
	}
	if err := a.store.DeleteFolder(id); err != nil {
		writeErr(w, 500, "delete failed")
		return
	}
	writeJSON(w, 200, map[string]any{"success": true, "message": "Folder deleted successfully"})
}
func (a *App) handleFolderDownload(w http.ResponseWriter, r *http.Request, id string) {
	f, ok := a.store.GetFolder(id)
	if !ok || !f.ExpiryTime.After(time.Now()) {
		writeErr(w, 404, "folder not found or expired")
		return
	}
	selected := map[string]bool{}
	if q := r.URL.Query().Get("files"); q != "" {
		for _, x := range strings.Split(q, ",") {
			selected[x] = true
		}
	}
	files := a.store.FilesInFolder(id)
	w.Header().Set("Content-Type", "application/zip")
	name := cleanFilename(f.Title)
	if name == "file" || name == "" {
		name = "files"
	}
	w.Header().Set("Content-Disposition", `attachment; filename*=UTF-8''`+url.PathEscape(name+".zip"))
	zw := zip.NewWriter(w)
	defer zw.Close()
	used := map[string]int{}
	for _, rec := range files {
		if len(selected) > 0 && !selected[rec.ID] {
			continue
		}
		src, err := os.Open(a.store.ObjectPath(rec.StoredName))
		if err != nil {
			continue
		}
		zn := uniqueZipName(rec.Name, used)
		hdr := &zip.FileHeader{Name: zn, Method: zip.Deflate}
		hdr.SetMode(0600)
		dst, err := zw.CreateHeader(hdr)
		if err == nil {
			_, _ = io.Copy(dst, src)
		}
		src.Close()
	}
}

func (a *App) publicFile(r *http.Request, rec *FileRecord) map[string]any {
	return map[string]any{"id": rec.ID, "name": rec.Name, "size": rec.Size, "url": a.baseURL(r) + "/" + rec.ID + "/", "expiryTime": rec.ExpiryTime.UnixMilli()}
}
func (a *App) publicFileInfo(r *http.Request, rec *FileRecord) map[string]any {
	m := map[string]any{"id": rec.ID, "name": rec.Name, "size": rec.Size, "mimeType": rec.MimeType, "uploadTime": rec.UploadTime.UnixMilli(), "expiryTime": rec.ExpiryTime.UnixMilli(), "exists": true, "downloadUrl": "/" + rec.ID + "/download", "security": map[string]any{"hasWarning": rec.HasWarning, "warningLevel": rec.RiskLevel, "warningMessage": nil, "suspiciousPatterns": rec.SuspiciousPatterns}}
	if rec.FolderID != "" {
		m["folder"] = map[string]any{"id": rec.FolderID, "url": "/api/folder/" + rec.FolderID}
	}
	return m
}
func (a *App) publicFolder(r *http.Request, f *FolderRecord, withLimits bool) map[string]any {
	count, total := a.store.FolderStats(f.ID)
	m := map[string]any{"id": f.ID, "title": f.Title, "url": a.baseURL(r) + "/" + f.ID + "/", "downloadUrl": a.baseURL(r) + "/" + f.ID + "/download", "fileCount": count, "totalSize": total, "createdAt": f.CreatedAt.UnixMilli(), "expiryTime": f.ExpiryTime.UnixMilli()}
	if withLimits {
		m["maxFiles"] = 50
	}
	return m
}
func (a *App) baseURL(r *http.Request) string {
	if a.cfg.PublicBaseURL != "" {
		return a.cfg.PublicBaseURL
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if a.cfg.TrustProxy && r.Header.Get("X-Forwarded-Proto") != "" {
		scheme = r.Header.Get("X-Forwarded-Proto")
	}
	return scheme + "://" + r.Host
}

func (a *App) cleanupLoop() {
	t := time.NewTicker(a.cfg.CleanupInterval)
	defer t.Stop()
	for range t.C {
		n, err := a.store.CleanupExpired(time.Now())
		if err != nil {
			log.Printf("cleanup error: %v", err)
		} else if n > 0 {
			log.Printf("cleanup removed %d expired objects", n)
		}
		a.uploadLimiter.Cleanup()
		a.downloadLimiter.Cleanup()
		a.globalLimiter.Cleanup()
	}
}

func deleteToken(r *http.Request) string {
	if t := r.Header.Get("X-Delete-Token"); t != "" {
		return t
	}
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	return ""
}
func folderToken(r *http.Request) string {
	if t := r.Header.Get("X-Folder-Token"); t != "" {
		return t
	}
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	return ""
}
func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}
func parsePositions(s string) []int {
	out := []int{}
	for _, x := range strings.Split(s, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil && n >= 0 {
			out = append(out, n)
		}
	}
	return out
}
func statusFromUploadErr(err error) int {
	if strings.Contains(err.Error(), "too large") {
		return 413
	}
	return 400
}
func maskIP(s string) string {
	if strings.Contains(s, ":") {
		parts := strings.Split(s, ":")
		if len(parts) > 3 {
			return strings.Join(parts[:3], ":") + ":xxxx"
		}
	}
	p := strings.Split(s, ".")
	if len(p) == 4 {
		return strings.Join(p[:3], ".") + ".xxx"
	}
	return s
}
func lastPrefix(a []string, p string) string {
	for _, s := range a {
		if strings.HasPrefix(s, p) {
			return s
		}
	}
	return ""
}
func withoutPrefix(a []string, p string) []string {
	out := []string{}
	for _, s := range a {
		if !strings.HasPrefix(s, p) {
			out = append(out, s)
		}
	}
	return out
}
func uniqueZipName(name string, used map[string]int) string {
	name = cleanFilename(name)
	n := used[name]
	used[name] = n + 1
	if n == 0 {
		return name
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	return fmt.Sprintf("%s (%d)%s", base, n+1, ext)
}

var _ = bytes.MinRead
var _ = context.Canceled
