package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// scanWithClamAV uses clamd's INSTREAM protocol. It never executes the file.
func scanWithClamAV(path, addr string) error {
	if strings.TrimSpace(addr) == "" {
		return nil
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("clamav unavailable: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))

	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return fmt.Errorf("clamav command failed: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := make([]byte, 32*1024)
	var lenbuf [4]byte
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(lenbuf[:], uint32(n))
			if _, err := conn.Write(lenbuf[:]); err != nil {
				return fmt.Errorf("clamav stream failed: %w", err)
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return fmt.Errorf("clamav stream failed: %w", err)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	binary.BigEndian.PutUint32(lenbuf[:], 0)
	if _, err := conn.Write(lenbuf[:]); err != nil {
		return fmt.Errorf("clamav stream end failed: %w", err)
	}

	reply, err := bufio.NewReader(conn).ReadString('\x00')
	if err != nil && err != io.EOF {
		return fmt.Errorf("clamav response failed: %w", err)
	}
	reply = strings.TrimSpace(strings.TrimSuffix(reply, "\x00"))
	if strings.Contains(reply, " FOUND") {
		return fmt.Errorf("malware detected by ClamAV: %s", reply)
	}
	if strings.Contains(reply, " ERROR") {
		return fmt.Errorf("clamav scan error: %s", reply)
	}
	if !strings.Contains(reply, " OK") {
		return fmt.Errorf("unexpected clamav response: %s", reply)
	}
	return nil
}
