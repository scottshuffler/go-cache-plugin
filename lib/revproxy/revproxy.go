// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package revproxy implements a minimal HTTP reverse proxy that caches files
// locally on disk, backed by objects in an S3 bucket.
//
// # Limitations
//
// By default, only objects marked "immutable" by the target server are
// eligible to be cached. Volatile objects that specify a max-age are also
// cached in-memory, but are not persisted on disk or in S3. If we think it's
// worthwhile we can spend some time to add more elaborate cache pruning, but
// for now we're doing the simpler thing.
package revproxy

import (
	"bytes"
	"crypto/sha256"
	"expvar"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/creachadair/mds/cache"
	"github.com/creachadair/mds/mapset"
	"github.com/creachadair/scheddle"
	"github.com/creachadair/taskgroup"
	"github.com/tailscale/go-cache-plugin/lib/s3util"
)

// Server is a caching reverse proxy server that caches successful responses to
// GET requests for certain designated domains.
//
// The host field of the request URL must match one of the configured targets.
// If not, the request is rejected with HTTP 502 (Bad Gateway).  Otherwise, the
// request is forwarded.  A successful response will be cached if the server's
// Cache-Control does not include "no-store", and does include "immutable".
//
// In addition, a successful response that is not immutable and specifies a
// max-age will be cached temporarily in-memory.
//
// # Cache Format
//
// A cached response is a file with a header section and the body, separated by
// a blank line. Only a subset of response headers are saved.
//
// # Cache Responses
//
// For requests handled by the proxy, the response includes an "X-Cache" header
// indicating how the response was obtained:
//
//   - "hit, memory": The response was served out of the memory cache.
//   - "hit, local": The response was served out of the local cache.
//   - "hit, remote": The response was faulted in from S3.
//   - "fetch, cached": The response was forwarded to the target and cached.
//   - "fetch, uncached": The response was forwarded to the target and not cached.
//
// For results intersecting with the cache, it also reports a X-Cache-Id giving
// the storage key of the cache object.
type Server struct {
	// Targets is the list of hosts for which the proxy should forward requests.
	// Host names should be fully-qualified ("host.example.com").
	Targets []string

	// Local is the path of a local cache directory where responses are cached.
	// It must be non-empty.
	Local string

	// S3Client is the S3 client used to read and write cache entries to the
	// backing store. It must be non-nil
	S3Client *s3util.Client

	// KeyPrefix, if non-empty, is prepended to each key stored into S3, with an
	// intervening slash.
	KeyPrefix string

	// Logf, if non-nil, is used to write log messages. If nil, logs are
	// discarded.
	Logf func(string, ...any)

	// LogRequests, if true, enables detailed (but noisy) debug logging of all
	// requests handled by the reverse proxy. Logs are written to Logf.
	//
	// Each request is presented in the format:
	//
	//     B U:"<url>" H:<digest> C:<bool>
	//     E H:<digest> <disposition> B:<bytes> (<time> elapsed)
	//     - H:<digest> miss
	//
	// The "B" line is when the request began, and "E" when it was finished.
	// The abbreviated fields are:
	//
	//     U:       -- request URL
	//     H:       -- request URL digest (cache key)
	//     C:       -- whether the request is cacheable (true/false)
	//     B:       -- body size in bytes (for hits)
	//
	// The dispositions of a request are:
	//
	//     hit mem  -- cache hit in memory (volatile)
	//     hit disk -- cache hit in local disk
	//     hit S3   -- cache hit in S3 (faulted to disk)
	//     fetch    -- fetched from the origin server
	//
	// On fetches, the "RC" tag indicates whether the response is cacheable,
	// with "no" meaning it was not cached at all, "mem" meaning it was cached
	// as a short-lived volatile response in memory, and "yes" meaning it was
	// cached on disk (and S3).
	LogRequests bool

	initOnce sync.Once
	tasks    *taskgroup.Group
	start    func(taskgroup.Task)
	mcache   *cache.Cache[string, memCacheEntry] // short-lived mutable objects
	expire   *scheddle.Queue                     // cache expirations

	reqReceived  expvar.Int // total requests received
	reqMemoryHit expvar.Int // hit in memory cache (volatile)
	reqLocalHit  expvar.Int // hit in local cache
	reqLocalMiss expvar.Int // miss in local cache
	reqFaultHit  expvar.Int // hit in remote (S3) cache
	reqFaultMiss expvar.Int // miss in remote (S3) cache
	reqForward   expvar.Int // request forwarded directly to upstream
	rspSave      expvar.Int // successful response saved in local cache
	rspSaveMem   expvar.Int // response saved in memory cache
	rspSaveError expvar.Int // error saving to local cache
	rspSaveBytes expvar.Int // bytes written to local cache
	rspPush      expvar.Int // successful response saved in S3
	rspPushError expvar.Int // error saving to S3
	rspPushBytes expvar.Int // bytes written to S3
	rspNotCached expvar.Int // response not cached anywhere
}

func (s *Server) init() {
	s.initOnce.Do(func() {
		nt := runtime.NumCPU()
		s.tasks, s.start = taskgroup.New(nil).Limit(nt)
		s.mcache = cache.New(cache.LRU[string, memCacheEntry](10 << 20).
			WithSize(entrySize),
		)
		s.expire = scheddle.NewQueue(nil)
	})
}

// Metrics returns a map of cache server metrics for s.  The caller is
// responsible to publish these metrics as desired.
func (s *Server) Metrics() *expvar.Map {
	m := new(expvar.Map)
	m.Set("req_received", &s.reqReceived)
	m.Set("req_memory_hit", &s.reqMemoryHit)
	m.Set("req_local_hit", &s.reqLocalHit)
	m.Set("req_local_miss", &s.reqLocalMiss)
	m.Set("req_fault_hit", &s.reqFaultHit)
	m.Set("req_fault_miss", &s.reqFaultMiss)
	m.Set("req_forward", &s.reqForward)
	m.Set("rsp_save", &s.rspSave)
	m.Set("rsp_save_memory", &s.rspSaveMem)
	m.Set("rsp_save_error", &s.rspSaveError)
	m.Set("rsp_save_bytes", &s.rspSaveBytes)
	m.Set("rsp_push", &s.rspPush)
	m.Set("rsp_push_error", &s.rspPushError)
	m.Set("rsp_push_bytes", &s.rspPushBytes)
	m.Set("rsp_not_cached", &s.rspNotCached)
	return m
}

// ServeHTTP implements the [http.Handler] interface for the proxy.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.init()
	s.reqReceived.Add(1)

	// Check whether this request is to a target we are permitted to proxy for.
	if !hostMatchesTarget(r.Host, s.Targets) {
		s.logf("reject proxy request for non-target %q", r.Host)
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}

	hash := hashRequestURL(r.URL)
	canCache := s.canCacheRequest(r)
	s.vlogf("rp B U:%q H:%s C:%v", r.URL, hash, canCache)
	start := time.Now()
	if canCache {
		// Check for a hit on this object in the memory cache.
		if data, hdr, err := s.cacheLoadMemory(hash); err == nil {
			s.reqMemoryHit.Add(1)
			setXCacheInfo(hdr, "hit, memory", hash)
			writeCachedResponse(w, hdr, data)
			s.vlogf("rp E H:%s hit mem B:%d (%v elapsed)", hash, len(data), time.Since(start))
			return
		}

		// Check for a hit on this object in the local cache.
		if data, hdr, err := s.cacheLoadLocal(hash); err == nil {
			s.reqLocalHit.Add(1)
			setXCacheInfo(hdr, "hit, local", hash)
			writeCachedResponse(w, hdr, data)
			s.vlogf("rp E H:%s hit disk B:%d (%v elapsed)", hash, len(data), time.Since(start))
			return
		}
		s.reqLocalMiss.Add(1)

		// Fault in from S3.
		if data, hdr, err := s.cacheLoadS3(r.Context(), hash); err == nil {
			s.reqFaultHit.Add(1)
			if err := s.cacheStoreLocal(hash, hdr, data); err != nil {
				s.logf("update %q local: %v", hash, err)
			}
			setXCacheInfo(hdr, "hit, remote", hash)
			writeCachedResponse(w, hdr, data)
			s.vlogf("rp E H:%s hit S3 B:%d (%v elapsed)", hash, len(data), time.Since(start))
			return
		}
		s.reqFaultMiss.Add(1)
		s.vlogf("rp - H:%s miss", hash)
	}

	// Reaching here, the object is not already cached locally so we have to
	// talk to the backend to get it. We need to do this whether or not it is
	// cacheable. Note we handle each request with its own proxy instance, so
	// that we can handle each response in context of this request.
	s.reqForward.Add(1)
	proxy := &httputil.ReverseProxy{Rewrite: s.rewriteRequest}
	updateCache := func() {}
	if canCache {
		proxy.ModifyResponse = func(rsp *http.Response) error {
			maxAge, isVolatile := s.canMemoryCache(rsp)
			canCacheResponse := s.canCacheResponse(rsp)
			if !canCacheResponse && !isVolatile {
				// A response we cannot cache at all.
				setXCacheInfo(rsp.Header, "fetch, uncached", "")
				s.rspNotCached.Add(1)
				s.vlogf("rp E H:%s fetch RC:no (%v elapsed)", hash, time.Since(start))
				return nil
			}

			// Read out the whole response body so we can update the cache, and
			// replace the response reader so we can copy it back to the caller.
			var buf bytes.Buffer
			rsp.Body = copyReader{
				Reader: io.TeeReader(rsp.Body, &buf),
				Closer: rsp.Body,
			}
			if !canCacheResponse && isVolatile {
				// A volatile response we can cache temporarily.
				setXCacheInfo(rsp.Header, "fetch, cached, volatile", hash)
				updateCache = func() {
					body := buf.Bytes()
					s.cacheStoreMemory(hash, maxAge, rsp.Header, body)
					s.rspSaveMem.Add(1)

					// N.B. Don't persist on disk or in S3.
					s.vlogf("rp E H:%s fetch RC:mem B:%d (%v elapsed)", hash, len(body), time.Since(start))
				}
			} else {
				setXCacheInfo(rsp.Header, "fetch, cached", hash)
				updateCache = func() {
					body := buf.Bytes()
					if err := s.cacheStoreLocal(hash, rsp.Header, body); err != nil {
						s.rspSaveError.Add(1)
						s.logf("save %q to cache: %v", hash, err)

						// N.B.: Don't bother trying to forward to S3 in this case.
					} else {
						s.rspSave.Add(1)
						s.rspSaveBytes.Add(int64(len(body)))
						s.start(s.cacheStoreS3(hash, rsp.Header, body))
					}
					s.vlogf("rp E H:%s fetch RC:yes B:%d (%v elapsed)", hash, len(body), time.Since(start))
				}
			}
			return nil
		}
	}
	proxy.ServeHTTP(w, r)
	updateCache()
}

// rewriteRequest rewrites the inbound request for routing to a target.
func (s *Server) rewriteRequest(pr *httputil.ProxyRequest) {
	u, _ := url.ParseRequestURI(pr.In.RequestURI)
	u.Host = pr.In.Host
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	pr.Out.URL = u
	pr.Out.Host = u.Host
}

type copyReader struct {
	io.Reader
	io.Closer
}

// makePath returns the local cache path for the specified request hash.
func (s *Server) makePath(hash string) string { return filepath.Join(s.Local, hash[:2], hash) }

// makeKey returns the S3 object key for the specified request hash.
func (s *Server) makeKey(hash string) string { return path.Join(s.KeyPrefix, hash[:2], hash) }

func (s *Server) logf(msg string, args ...any) {
	if s.Logf != nil {
		s.Logf(msg, args...)
	}
}

func (s *Server) vlogf(msg string, args ...any) {
	if s.LogRequests {
		s.logf(msg, args...)
	}
}

func hostMatchesTarget(host string, targets []string) bool {
	return slices.Contains(targets, host)
}

// canCacheRequest reports whether r is a request whose response can be cached.
func (s *Server) canCacheRequest(r *http.Request) bool {
	return r.Method == "GET" && !parseCacheControl(r.Header.Get("Cache-Control")).Keys.Has("no-store")
}

// canCacheResponse reports whether r is a response whose body can be cached.
func (s *Server) canCacheResponse(rsp *http.Response) bool {
	if rsp.StatusCode != http.StatusOK {
		return false
	}
	cc := parseCacheControl(rsp.Header.Get("Cache-Control"))
	if cc.Keys.Has("no-store") {
		return false
	} else if cc.Keys.Has("immutable") {
		return true
	}

	// We treat a response that is not immutable but requires validation as
	// cacheable if its max-age is so long it doesn't matter.
	const goodLongTime = 60 * 24 * time.Hour
	return cc.Keys.Has("must-revalidate") && cc.MaxAge > goodLongTime
}

type cacheControl struct {
	Keys   mapset.Set[string]
	MaxAge time.Duration
}

func parseCacheControl(s string) (out cacheControl) {
	for _, v := range strings.Split(s, ",") {
		key, val, ok := strings.Cut(strings.TrimSpace(v), "=")
		if ok && key == "max-age" {
			sec, err := strconv.Atoi(val)
			if err == nil {
				out.MaxAge = time.Duration(sec) * time.Second
			}
		}
		out.Keys.Add(key)
	}
	return
}

// canMemoryCache reports whether r is a volatile response whose body can be
// cached temporarily, and if so returns the maxmimum length of time the cache
// entry should be valid for.
func (s *Server) canMemoryCache(rsp *http.Response) (time.Duration, bool) {
	if rsp.StatusCode != http.StatusOK {
		return 0, false
	}
	cc := parseCacheControl(rsp.Header.Get("Cache-Control"))
	if cc.Keys.Has("no-store") || cc.Keys.Has("no-cache") {
		// While no-cache doesn't mean we can't cache it, it requires
		// re-validation before reusing the response, so treat that as if it were
		// no-store.
		return 0, false
	}

	// We'll cache things in memory if they aren't expected to last too long.
	if cc.MaxAge > 0 && cc.MaxAge < time.Hour {
		return cc.MaxAge, true
	}
	return 0, false
}

// hashRequest generates the storage digest for the specified request URL.
func hashRequestURL(u *url.URL) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(u.String())))
}

// writeCachedResponse generates an HTTP response for a cached result using the
// provided headers and body from the cache object.
func writeCachedResponse(w http.ResponseWriter, hdr http.Header, body []byte) {
	wh := w.Header()
	for name, vals := range hdr {
		for _, val := range vals {
			wh.Add(name, val)
		}
	}
	w.Write(body)
}
