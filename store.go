package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type Store struct {
	mu        sync.RWMutex
	root      string
	objects   string
	indexPath string
	idx       DiskIndex
}

func NewStore(root string) (*Store, error) {
	s := &Store{root: root, objects: filepath.Join(root, "objects"), indexPath: filepath.Join(root, "index.json")}
	if err := os.MkdirAll(s.objects, 0700); err != nil {
		return nil, err
	}
	s.idx.Files = map[string]*FileRecord{}
	s.idx.Folders = map[string]*FolderRecord{}
	b, err := os.ReadFile(s.indexPath)
	if err == nil {
		if err = json.Unmarshal(b, &s.idx); err != nil {
			return nil, fmt.Errorf("load index: %w", err)
		}
		if s.idx.Files == nil {
			s.idx.Files = map[string]*FileRecord{}
		}
		if s.idx.Folders == nil {
			s.idx.Folders = map[string]*FolderRecord{}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

func (s *Store) persistLocked() error {
	b, err := json.MarshalIndent(s.idx, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.indexPath + ".tmp"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.indexPath)
}

func (s *Store) ObjectPath(stored string) string { return filepath.Join(s.objects, stored) }

func (s *Store) PutFile(rec *FileRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.idx.Files[rec.ID] = rec
	return s.persistLocked()
}

func (s *Store) GetFile(id string) (*FileRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.idx.Files[id]
	if !ok {
		return nil, false
	}
	cp := *r
	cp.SuspiciousPatterns = append([]string(nil), r.SuspiciousPatterns...)
	cp.Recommendations = append([]string(nil), r.Recommendations...)
	return &cp, true
}

func (s *Store) DeleteFile(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.idx.Files[id]
	if !ok {
		return os.ErrNotExist
	}
	_ = os.Remove(s.ObjectPath(r.StoredName))
	delete(s.idx.Files, id)
	return s.persistLocked()
}

func (s *Store) PutFolder(f *FolderRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.idx.Folders[f.ID] = f
	return s.persistLocked()
}
func (s *Store) GetFolder(id string) (*FolderRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.idx.Folders[id]
	if !ok {
		return nil, false
	}
	cp := *f
	return &cp, true
}
func (s *Store) FilesInFolder(id string) []*FileRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []*FileRecord{}
	for _, r := range s.idx.Files {
		if r.FolderID == id {
			cp := *r
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Position < out[j].Position })
	return out
}
func (s *Store) FolderStats(id string) (count int, total int64) {
	for _, f := range s.FilesInFolder(id) {
		count++
		total += f.Size
	}
	return
}

func (s *Store) DeleteFolder(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.idx.Folders[id]; !ok {
		return os.ErrNotExist
	}
	for fid, r := range s.idx.Files {
		if r.FolderID == id {
			_ = os.Remove(s.ObjectPath(r.StoredName))
			delete(s.idx.Files, fid)
		}
	}
	delete(s.idx.Folders, id)
	return s.persistLocked()
}

func (s *Store) RenameFolder(id, title string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.idx.Folders[id]
	if !ok {
		return os.ErrNotExist
	}
	f.Title = title
	return s.persistLocked()
}

func (s *Store) CleanupExpired(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, r := range s.idx.Files {
		if !r.ExpiryTime.After(now) {
			_ = os.Remove(s.ObjectPath(r.StoredName))
			delete(s.idx.Files, id)
			n++
		}
	}
	for id, f := range s.idx.Folders {
		if !f.ExpiryTime.After(now) {
			for fid, r := range s.idx.Files {
				if r.FolderID == id {
					_ = os.Remove(s.ObjectPath(r.StoredName))
					delete(s.idx.Files, fid)
					n++
				}
			}
			delete(s.idx.Folders, id)
		}
	}
	if n > 0 {
		return n, s.persistLocked()
	}
	return 0, nil
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
func tokenEqual(hash, token string) bool {
	a, err := hex.DecodeString(hash)
	if err != nil {
		return false
	}
	b := sha256.Sum256([]byte(token))
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b[:]) == 1
}
