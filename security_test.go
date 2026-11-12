package main

import (
	"archive/zip"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestPublicIPGuard(t *testing.T) {
	blocked := []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "::1", "fe80::1"}
	for _, s := range blocked {
		if ip := net.ParseIP(s); isPublicIP(ip) {
			t.Fatalf("expected %s to be blocked", s)
		}
	}
	if !isPublicIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("expected public IP to be allowed")
	}
}

func TestRejectScriptContent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho unsafe\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := scanFile(p, "note.txt", loadConfig()); err == nil {
		t.Fatal("expected script content to be rejected")
	}
}

func TestRejectExtensionMismatch(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "fake.pdf")
	if err := os.WriteFile(p, []byte("this is not a pdf"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := scanFile(p, "fake.pdf", loadConfig()); err == nil {
		t.Fatal("expected extension/MIME mismatch to be rejected")
	}
}

func TestRejectZipTraversal(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("../evil.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("x"))
	_ = zw.Close()
	_ = f.Close()
	if _, err := scanFile(p, "bad.zip", loadConfig()); err == nil {
		t.Fatal("expected traversal ZIP to be rejected")
	}
}
