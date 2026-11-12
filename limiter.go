package main

import (
	"sync"
	"time"
)

type counter struct {
	Start time.Time
	Count int
}
type FixedWindowLimiter struct {
	mu     sync.Mutex
	window time.Duration
	limit  int
	items  map[string]counter
}

func NewLimiter(window time.Duration, limit int) *FixedWindowLimiter {
	return &FixedWindowLimiter{window: window, limit: limit, items: map[string]counter{}}
}
func (l *FixedWindowLimiter) Allow(key string) (bool, int, time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	c := l.items[key]
	if c.Start.IsZero() || now.Sub(c.Start) >= l.window {
		c = counter{Start: now}
	}
	if c.Count >= l.limit {
		return false, 0, c.Start.Add(l.window)
	}
	c.Count++
	l.items[key] = c
	return true, l.limit - c.Count, c.Start.Add(l.window)
}
func (l *FixedWindowLimiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for k, c := range l.items {
		if now.Sub(c.Start) >= 2*l.window {
			delete(l.items, k)
		}
	}
}
