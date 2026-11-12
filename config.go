package main

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr            string
	DataDir               string
	PublicBaseURL         string
	MaxFileSize           int64
	MaxFilesPerRequest    int
	RequireDeleteToken    bool
	TrustProxy            bool
	URLImportPorts        map[string]bool
	CleanupInterval       time.Duration
	ClamAVAddr            string
	ClamAVFailOpen        bool
	MaxZipEntries         int
	MaxZipUncompressed    int64
	MaxZipCompressionRate float64
}

func loadConfig() Config {
	return Config{
		ListenAddr:            env("LISTEN_ADDR", ":8080"),
		DataDir:               env("DATA_DIR", "./data"),
		PublicBaseURL:         strings.TrimRight(os.Getenv("PUBLIC_BASE_URL"), "/"),
		MaxFileSize:           envInt64("MAX_FILE_SIZE", 100*1024*1024),
		MaxFilesPerRequest:    envInt("MAX_FILES_PER_REQUEST", 20),
		RequireDeleteToken:    envBool("REQUIRE_DELETE_TOKEN", true),
		TrustProxy:            envBool("TRUST_PROXY", false),
		URLImportPorts:        parsePorts(env("URL_IMPORT_PORTS", "80,443")),
		CleanupInterval:       envDuration("CLEANUP_INTERVAL", time.Minute),
		ClamAVAddr:            strings.TrimSpace(os.Getenv("CLAMAV_ADDR")),
		ClamAVFailOpen:        envBool("CLAMAV_FAIL_OPEN", false),
		MaxZipEntries:         envInt("MAX_ZIP_ENTRIES", 2000),
		MaxZipUncompressed:    envInt64("MAX_ZIP_UNCOMPRESSED", 200*1024*1024),
		MaxZipCompressionRate: envFloat("MAX_ZIP_COMPRESSION_RATIO", 100),
	}
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func envInt(k string, d int) int {
	v, e := strconv.Atoi(env(k, strconv.Itoa(d)))
	if e != nil || v <= 0 {
		return d
	}
	return v
}
func envInt64(k string, d int64) int64 {
	v, e := strconv.ParseInt(env(k, strconv.FormatInt(d, 10)), 10, 64)
	if e != nil || v <= 0 {
		return d
	}
	return v
}
func envFloat(k string, d float64) float64 {
	v, e := strconv.ParseFloat(env(k, strconv.FormatFloat(d, 'f', -1, 64)), 64)
	if e != nil || v <= 0 {
		return d
	}
	return v
}
func envBool(k string, d bool) bool {
	v := strings.ToLower(os.Getenv(k))
	if v == "" {
		return d
	}
	return v == "1" || v == "true" || v == "yes"
}
func envDuration(k string, d time.Duration) time.Duration {
	v, e := time.ParseDuration(env(k, d.String()))
	if e != nil {
		return d
	}
	return v
}
func parsePorts(s string) map[string]bool {
	m := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			m[p] = true
		}
	}
	return m
}
