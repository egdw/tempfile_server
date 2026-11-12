package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func randomID(n int) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	b := make([]byte, n)
	raw := make([]byte, n)
	_, _ = rand.Read(raw)
	for i := range b {
		b[i] = alphabet[int(raw[i])%len(alphabet)]
	}
	return string(b)
}
func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func cleanFilename(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	name = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if name == "" || name == "." {
		return "file"
	}
	r := []rune(name)
	if len(r) > 180 {
		name = string(r[:180])
	}
	return name
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeErr(w http.ResponseWriter, status int, msg string, code ...string) {
	m := map[string]any{"success": false, "error": msg}
	if len(code) > 0 {
		m["code"] = code[0]
	}
	writeJSON(w, status, m)
}
func parseExpiry(s string) (time.Duration, error) {
	if s == "" {
		s = "1"
	}
	h, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	switch h {
	case 1, 6, 24, 48:
		return time.Duration(h) * time.Hour, nil
	default:
		return 0, fmt.Errorf("expiryHours must be one of 1, 6, 24, 48")
	}
}
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if x := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); x != "" {
			return x
		}
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return h
	}
	return r.RemoteAddr
}
func validID(id string, n int) bool { return len(id) == n && idRE.MatchString(id) }
