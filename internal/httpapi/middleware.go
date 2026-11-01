package httpapi

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// APIKeyMiddleware protects all routes when a non-empty API key is configured.
func APIKeyMiddleware(apiKey string, next http.Handler) http.Handler {
	if apiKey == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := r.Header.Get("X-API-Key")
		if len(provided) != len(apiKey) || subtle.ConstantTimeCompare([]byte(provided), []byte(apiKey)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "Unauthorized", "details": "A valid X-API-Key header is required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

type visitor struct {
	windowStart time.Time
	count       int
}

// RateLimitMiddleware applies a fixed-window limit per client IP.
func RateLimitMiddleware(limit int, window time.Duration, next http.Handler) http.Handler {
	if limit <= 0 || window <= 0 {
		return next
	}
	var mu sync.Mutex
	visitors := make(map[string]visitor)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		now := time.Now()

		mu.Lock()
		current := visitors[ip]
		if current.windowStart.IsZero() || now.Sub(current.windowStart) >= window {
			current = visitor{windowStart: now}
		}
		current.count++
		visitors[ip] = current

		// Periodically remove expired entries to keep memory bounded.
		if len(visitors) > 1024 {
			for key, item := range visitors {
				if now.Sub(item.windowStart) >= window {
					delete(visitors, key)
				}
			}
		}
		mu.Unlock()

		if current.count > limit {
			w.Header().Set("Retry-After", durationSeconds(window-now.Sub(current.windowStart)))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"message": "Rate limit exceeded"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	// Do not trust X-Forwarded-For unless a trusted reverse proxy is configured.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func durationSeconds(duration time.Duration) string {
	seconds := int(duration.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return strconv.Itoa(seconds)
}
