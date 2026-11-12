package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type ScanResult struct {
	MimeType        string
	HasWarning      bool
	RiskLevel       string
	Patterns        []string
	Recommendations []string
}

var blockedExtensions = map[string]bool{
	".exe": true, ".dll": true, ".com": true, ".scr": true, ".msi": true, ".msp": true,
	".bat": true, ".cmd": true, ".ps1": true, ".psm1": true, ".vbs": true, ".vbe": true, ".js": true, ".jse": true, ".wsf": true,
	".sh": true, ".bash": true, ".zsh": true, ".fish": true, ".py": true, ".pyw": true, ".pl": true, ".rb": true, ".php": true, ".phar": true,
	".jar": true, ".war": true, ".apk": true, ".app": true, ".dmg": true, ".iso": true, ".img": true, ".deb": true, ".rpm": true,
	".hta": true, ".lnk": true, ".url": true, ".reg": true, ".inf": true, ".scf": true, ".cpl": true, ".sys": true,
	".html": true, ".htm": true, ".xhtml": true, ".svg": true, ".xml": false,
	".docm": true, ".xlsm": true, ".pptm": true, ".xlam": true, ".dotm": true,
	".rar": true, ".7z": true, ".tar": true, ".gz": true, ".bz2": true, ".xz": true,
}

var allowedMimePrefixes = []string{"image/", "audio/", "video/", "text/plain"}
var allowedExactMimes = map[string]bool{
	"application/pdf": true,
	"application/zip": true,
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document":   true,
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         true,
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": true,
	"application/msword":            true,
	"application/vnd.ms-excel":      true,
	"application/vnd.ms-powerpoint": true,
	"application/json":              true,
	"application/xml":               true,
	"text/csv":                      true,
}

func scanFile(path, name string, cfg Config) (ScanResult, error) {
	ext := strings.ToLower(filepath.Ext(name))
	if blockedExtensions[ext] {
		return ScanResult{}, fmt.Errorf("file type %s is blocked", ext)
	}
	f, err := osOpen(path)
	if err != nil {
		return ScanResult{}, err
	}
	defer f.Close()
	head := make([]byte, 8192)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	if looksExecutable(head) {
		return ScanResult{}, fmt.Errorf("native executable content is blocked")
	}
	if looksScript(head) {
		return ScanResult{}, fmt.Errorf("script content is blocked")
	}
	detected := http.DetectContentType(head)
	// Prefer extension MIME for Office ZIP containers, but only after archive inspection.
	extMime := mime.TypeByExtension(ext)
	if i := strings.Index(extMime, ";"); i >= 0 {
		extMime = extMime[:i]
	}
	if ext == ".zip" || isOfficeExt(ext) {
		if err := scanZip(path, cfg); err != nil {
			return ScanResult{}, err
		}
		if extMime != "" {
			detected = extMime
		} else {
			detected = "application/zip"
		}
	}
	if !isAllowedMime(detected) {
		return ScanResult{}, fmt.Errorf("MIME type %q is not allowed", detected)
	}
	if err := validateExtensionMime(ext, detected); err != nil {
		return ScanResult{}, err
	}
	patterns := findSuspiciousPatterns(head)
	r := ScanResult{MimeType: detected, RiskLevel: "safe"}
	if len(patterns) > 0 {
		r.HasWarning = true
		r.RiskLevel = "low"
		r.Patterns = patterns
		r.Recommendations = []string{"Treat the file as untrusted data", "Do not execute embedded content", "Scan again with endpoint protection before opening"}
	}
	return r, nil
}

// indirection keeps testing/mocking simple without shelling out.
var osOpen = func(name string) (io.ReadCloser, error) { return os.Open(name) }

func validateExtensionMime(ext, detected string) error {
	m := strings.ToLower(strings.TrimSpace(strings.Split(detected, ";")[0]))
	expected := map[string][]string{
		".pdf":  {"application/pdf"},
		".png":  {"image/png"},
		".jpg":  {"image/jpeg"},
		".jpeg": {"image/jpeg"},
		".gif":  {"image/gif"},
		".webp": {"image/webp"},
		".zip":  {"application/zip"},
		".docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
		".xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
		".pptx": {"application/vnd.openxmlformats-officedocument.presentationml.presentation"},
	}
	allowed, ok := expected[ext]
	if !ok {
		return nil
	}
	for _, want := range allowed {
		if m == want {
			return nil
		}
	}
	return fmt.Errorf("file extension %s does not match detected MIME type %q", ext, detected)
}
func isAllowedMime(m string) bool {
	m = strings.ToLower(strings.TrimSpace(strings.Split(m, ";")[0]))
	if allowedExactMimes[m] {
		return true
	}
	for _, p := range allowedMimePrefixes {
		if strings.HasPrefix(m, p) {
			return true
		}
	}
	return false
}
func isOfficeExt(ext string) bool {
	switch ext {
	case ".docx", ".xlsx", ".pptx":
		return true
	}
	return false
}
func looksScript(b []byte) bool {
	s := strings.ToLower(string(bytes.TrimSpace(b)))
	return strings.HasPrefix(s, "#!") || strings.HasPrefix(s, "<script") || strings.HasPrefix(s, "<?php") || strings.HasPrefix(s, "<html") || strings.Contains(s, "<script ")
}
func looksExecutable(b []byte) bool {
	if len(b) >= 2 && b[0] == 'M' && b[1] == 'Z' {
		return true
	}
	if len(b) >= 4 && bytes.Equal(b[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return true
	}
	if len(b) >= 4 {
		m := binary.BigEndian.Uint32(b[:4])
		switch m {
		case 0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcefaedfe, 0xcffaedfe:
			return true
		}
	}
	return false
}
func findSuspiciousPatterns(b []byte) []string {
	s := strings.ToLower(string(b))
	keys := []string{"eval(", "exec(", "shell_exec", "powershell", "cmd.exe", "/bin/sh", "javascript:", "vbscript:"}
	out := []string{}
	for _, k := range keys {
		if strings.Contains(s, k) {
			out = append(out, k)
		}
	}
	return out
}

func scanZip(path string, cfg Config) error {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("invalid ZIP: %w", err)
	}
	defer zr.Close()
	if len(zr.File) > cfg.MaxZipEntries {
		return fmt.Errorf("ZIP has too many entries")
	}
	var total uint64
	for _, zf := range zr.File {
		clean := filepath.Clean(strings.ReplaceAll(zf.Name, "\\", "/"))
		if strings.HasPrefix(clean, "../") || clean == ".." || filepath.IsAbs(clean) {
			return fmt.Errorf("ZIP contains path traversal entry")
		}
		ext := strings.ToLower(filepath.Ext(zf.Name))
		if blockedExtensions[ext] {
			return fmt.Errorf("ZIP contains blocked file type %s", ext)
		}
		total += zf.UncompressedSize64
		if total > uint64(cfg.MaxZipUncompressed) {
			return fmt.Errorf("ZIP uncompressed size exceeds limit")
		}
		if zf.CompressedSize64 > 0 && zf.UncompressedSize64 > 1024*1024 {
			ratio := float64(zf.UncompressedSize64) / float64(zf.CompressedSize64)
			if ratio > cfg.MaxZipCompressionRate {
				return fmt.Errorf("ZIP compression ratio is suspicious")
			}
		}
		if zf.UncompressedSize64 > 0 && zf.UncompressedSize64 < 2*1024*1024 {
			rc, err := zf.Open()
			if err != nil {
				return err
			}
			head := make([]byte, 8192)
			n, _ := io.ReadFull(io.LimitReader(rc, 8192), head)
			rc.Close()
			head = head[:n]
			if looksExecutable(head) || looksScript(head) {
				return fmt.Errorf("ZIP contains executable/script content")
			}
		}
	}
	return nil
}
