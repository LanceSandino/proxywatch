package fetch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"proxywatch/internal/config"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
func assertCode(t *testing.T, err error, code string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("want error %q, got %v", code, err)
	}
}

func TestPublicIPRejectsNonPublicRanges(t *testing.T) {
	for _, raw := range []string{"0.0.0.0", "0.12.1.2", "10.0.0.1", "127.0.0.1", "169.254.169.254", "172.16.1.1", "192.168.1.1", "100.64.0.1", "192.0.0.1", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255", "::", "::1", "fc00::1", "fd12::1", "fe80::1", "ff02::1", "2001:db8::1", "2001::1", "2002::1", "64:ff9b::a00:1", "::ffff:127.0.0.1", "::ffff:169.254.169.254"} {
		t.Run(raw, func(t *testing.T) {
			if PublicIP(netip.MustParseAddr(raw)) {
				t.Fatalf("unsafe address accepted: %s", raw)
			}
		})
	}
	if PublicIP(netip.Addr{}) {
		t.Fatal("invalid address accepted")
	}
	for _, raw := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		if !PublicIP(netip.MustParseAddr(raw)) {
			t.Fatalf("public address rejected: %s", raw)
		}
	}
}

func TestURLValidationBeforeAnyRequest(t *testing.T) {
	c := New(config.Config{AllowedHosts: []string{"8.8.8.8", "127.0.0.1", "169.254.169.254", "::1"}, TimeoutSeconds: 1, MaxBytes: 1024})
	tests := []struct{ url, code string }{
		{"file:///etc/passwd", "unsafe_url"}, {"ftp://8.8.8.8/data", "unsafe_url"}, {"//8.8.8.8/data", "unsafe_url"}, {"http://user:password@8.8.8.8/", "unsafe_url"}, {"https://8.8.8.8/#fragment", "unsafe_url"}, {"http://8.8.8.8:8080/", "unsafe_port"}, {"http://8.8.8.8:abc/", "unsafe_url"}, {"http://8.8.8.8.evil.invalid/", "host_not_allowed"}, {"http://1.1.1.1/", "host_not_allowed"}, {"http://127.0.0.1/", "unsafe_ip"}, {"http://169.254.169.254/latest/meta-data", "unsafe_ip"}, {"http://[::1]/", "unsafe_ip"},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) { assertCode(t, c.Validate(context.Background(), tt.url), tt.code) })
	}
	for _, raw := range []string{"https://8.8.8.8/", "http://8.8.8.8:80/", "https://8.8.8.8:443/"} {
		if err := c.Validate(context.Background(), raw); err != nil {
			t.Fatalf("valid URL %s: %v", raw, err)
		}
	}
	_, err := PublicIPs(context.Background(), "192.168.1.1")
	assertCode(t, err, "unsafe_ip")
}

func TestRedirectsAreNeverFollowed(t *testing.T) {
	calls := 0
	c := NewForTest(&http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls > 1 {
			t.Errorf("followed redirect to %s", r.URL)
			return response(200, "unsafe destination"), nil
		}
		res := response(302, "")
		res.Header.Set("Location", "http://169.254.169.254/latest/meta-data")
		return res, nil
	})})
	_, err := c.Get(context.Background(), "https://source.invalid/list", nil)
	assertCode(t, err, "redirect_rejected")
	if calls != 1 {
		t.Fatalf("want one source request, got %d", calls)
	}
}

func TestResponseLimitsAndSourceFailures(t *testing.T) {
	for _, tt := range []struct {
		name       string
		status     int
		body, code string
	}{{"too_large", 200, "12345", "response_too_large"}, {"missing", 404, "", "http_error"}, {"quota", 403, "", "access_or_quota_restricted"}, {"rate", 429, "", "rate_limited"}, {"failure", 503, "", "http_error"}} {
		t.Run(tt.name, func(t *testing.T) {
			closed := false
			c := NewForTest(&http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
				r := response(tt.status, tt.body)
				r.Body = &closeBody{Reader: strings.NewReader(tt.body), closed: &closed}
				return r, nil
			})})
			c.maxBytes = 4
			r, err := c.Get(context.Background(), "https://source.invalid/list", nil)
			assertCode(t, err, tt.code)
			if !closed {
				t.Fatal("response body leaked")
			}
			if tt.status != 200 && r.Status != tt.status {
				t.Fatalf("HTTP status lost: %+v", r)
			}
		})
	}
}

type closeBody struct {
	io.Reader
	closed *bool
}

func (b *closeBody) Close() error { *b.closed = true; return nil }

func TestCancellationTimeoutAndRateLimitWait(t *testing.T) {
	var calls atomic.Int32
	c := NewForTest(&http.Client{Timeout: 20 * time.Millisecond, Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})})
	start := time.Now()
	_, err := c.Get(context.Background(), "https://source.invalid/list", nil)
	assertCode(t, err, "network_or_timeout")
	if time.Since(start) > time.Second {
		t.Fatal("client timeout did not bound request")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = c.Get(ctx, "https://source.invalid/list", nil)
	assertCode(t, err, "cancelled")
	c.interval = time.Hour
	c.last["source.invalid"] = time.Now()
	before := calls.Load()
	_, err = c.Get(ctx, "https://source.invalid/list", nil)
	assertCode(t, err, "cancelled")
	if calls.Load() != before {
		t.Fatal("cancelled rate-limit wait made a request")
	}
}

func TestRobotsFailClosedAndCachePolicy(t *testing.T) {
	for _, tt := range []struct {
		name       string
		status     int
		body, code string
		pageCalls  int
	}{{"deny", 200, "User-agent: ProxyWatch\nDisallow: /private\n", "robots_denied", 0}, {"unavailable", 503, "", "robots_unavailable", 0}, {"restricted", 403, "", "robots_unavailable", 0}, {"quota", 429, "", "robots_unavailable", 0}, {"redirect", 302, "", "robots_unavailable", 0}, {"absent", 404, "", "", 2}, {"permitted", 200, "User-agent: *\nDisallow: /private\nAllow: /public\n", "", 2}} {
		t.Run(tt.name, func(t *testing.T) {
			robotsCalls, pageCalls := 0, 0
			c := NewForTest(&http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/robots.txt" {
					robotsCalls++
					res := response(tt.status, tt.body)
					if tt.status == 302 {
						res.Header.Set("Location", "http://127.0.0.1/robots.txt")
					}
					return res, nil
				}
				pageCalls++
				return response(200, "public list"), nil
			})})
			path := "/public"
			if tt.name == "deny" {
				path = "/private/list"
			}
			for i := 0; i < 2; i++ {
				_, err := c.PublicPage(context.Background(), "https://source.invalid"+path)
				if tt.code != "" {
					assertCode(t, err, tt.code)
				} else if err != nil {
					t.Fatal(err)
				}
			}
			if pageCalls != tt.pageCalls {
				t.Fatalf("page requests = %d; want %d", pageCalls, tt.pageCalls)
			}
			if tt.code == "" && robotsCalls != 1 {
				t.Fatalf("robots policy not cached: %d", robotsCalls)
			}
		})
	}
}

func TestRobotsNetworkErrorDoesNotFetchPage(t *testing.T) {
	calls := 0
	c := NewForTest(&http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, context.DeadlineExceeded })})
	_, err := c.PublicPage(context.Background(), "https://source.invalid/list")
	assertCode(t, err, "robots_unavailable")
	if calls != 3 {
		t.Fatalf("want three bounded robots attempts, got: %d", calls)
	}
}
func TestRobotsCrawlDelayIsHonoredOrSkipped(t *testing.T) {
	for _, tc := range []struct {
		delay string
		skip  bool
	}{{"0.02", false}, {"120", true}} {
		requests := 0
		c := NewForTest(&http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			requests++
			if r.URL.Path == "/robots.txt" {
				return response(200, "User-agent: *\nAllow: /\nCrawl-delay: "+tc.delay+"\n"), nil
			}
			return response(200, "public page"), nil
		})})
		started := time.Now()
		_, e := c.PublicPage(context.Background(), "https://source.invalid/page")
		if tc.skip {
			assertCode(t, e, "robots_crawl_delay_exceeds_limit")
			if requests != 1 {
				t.Fatal("page fetched despite excessive crawl delay")
			}
		} else {
			if e != nil {
				t.Fatal(e)
			}
			if time.Since(started) < 20*time.Millisecond || c.rates["source.invalid"] != 20*time.Millisecond {
				t.Fatal("robots crawl delay ignored")
			}
		}
	}
}
