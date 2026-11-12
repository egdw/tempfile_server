package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func buildSafeHTTPClient(cfg Config) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if !cfg.URLImportPorts[port] {
				return nil, fmt.Errorf("remote port %s is not allowed", port)
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			if len(ips) == 0 {
				return nil, errors.New("DNS returned no addresses")
			}
			for _, ip := range ips {
				if !isPublicIP(ip.IP) {
					return nil, fmt.Errorf("non-public destination is blocked")
				}
			}
			// Pin this connection to one validated IP to reduce DNS rebinding risk.
			target := net.JoinHostPort(ips[0].IP.String(), port)
			return dialer.DialContext(ctx, network, target)
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          10,
	}
	c := &http.Client{Transport: tr, Timeout: 2 * time.Minute}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		return validateImportURL(req.URL, cfg)
	}
	return c
}

func validateImportURL(u *url.URL, cfg Config) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("only http/https URLs are allowed")
	}
	if u.User != nil {
		return errors.New("URLs with credentials are blocked")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("missing host")
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	if !cfg.URLImportPorts[port] {
		return fmt.Errorf("port %s is not allowed", port)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if !isPublicIP(ip.IP) {
			return errors.New("non-public destination is blocked")
		}
	}
	return nil
}

func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	// Carrier-grade NAT 100.64.0.0/10
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return false
		}
		if v4[0] == 169 && v4[1] == 254 {
			return false
		}
		if v4[0] == 0 {
			return false
		}
	}
	s := strings.ToLower(ip.String())
	if strings.HasPrefix(s, "fc") || strings.HasPrefix(s, "fd") || strings.HasPrefix(s, "fe80:") {
		return false
	}
	return true
}
