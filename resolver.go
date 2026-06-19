// Copyright 2025 Bruno Schaatsbergen. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsdialer

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// resolver is the internal interface that all DNS resolver implementations must satisfy.
//
// This abstraction allows strategies to work with any resolver implementation
// (UDP, TCP, DNS-over-HTTPS, etc.) without knowing the transport details.
type resolver interface {
	// ResolveType performs a DNS query for a specific record type.
	// Returns records on success, or an error if the query fails.
	ResolveType(ctx context.Context, host string, qtype RecordType) ([]Record, error)

	// Name returns the identifier of this resolver (typically the server address).
	// Used for logging and in Compare strategy to identify which resolver returned what.
	Name() string
}

// Dialer is the main entry point for multiplexed DNS resolution.
//
// It coordinates multiple underlying DNS resolvers using a configurable strategy,
// enabling improved reliability, performance, or security compared to single-resolver
// approaches.
type Dialer struct {
	// resolvers is the list of DNS resolvers we'll query (e.g., UDP resolvers for 8.8.8.8, 1.1.1.1)
	resolvers []resolver

	// strategy determines how we coordinate queries (Race, Fallback, Consensus, Compare)
	strategy Strategy

	// timeout is the per-query timeout we apply to individual DNS queries
	timeout time.Duration

	// logger is the structured logging interface, no-op by default so zero overhead if you don't need it
	logger Logger

	// poolSize is the max connections to pool per resolver, defaults to 4
	poolSize int

	// dialer is reused for TCP/UDP connections to avoid allocating a new one each time
	dialer *net.Dialer

	// cache stores DNS lookup results with TTL-based expiration, disabled by default
	cache *dnsCache
}

// Logger provides structured logging throughout the resolution process.
type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Error(msg string, err error, fields ...Field)
}

// Field represents a structured logging field (key-value pair).
// Used to attach context to log messages.
type Field struct {
	Key   string
	Value interface{}
}

// noopLogger is the default logger that silently discards all log messages.
// This allows the library to have zero logging overhead when not needed.
type noopLogger struct{}

func (noopLogger) Debug(msg string, fields ...Field)            {}
func (noopLogger) Info(msg string, fields ...Field)             {}
func (noopLogger) Error(msg string, err error, fields ...Field) {}

// New creates a new Dialer with the given options.
//
// Default configuration:
//
//   - Strategy: Race (lowest latency)
//   - Timeout: 2 seconds per query
//   - Logger: no-op (no logging)
//   - Pool size: 4 connections per resolver
//   - Query types: [A, AAAA] (IPv4 and IPv6)
//   - Resolvers: none (must be set via WithResolvers)
//   - Cache: disabled (can be enabled via WithCache)
//
// Example:
//
//	dialer := New(
//	    WithResolvers("8.8.8.8", "1.1.1.1"),
//	    WithStrategy(Consensus{MinAgreement: 2}),
//	    WithTimeout(5 * time.Second),
//	    WithCache(1000, 1*time.Second, 5*time.Minute),
//	)
func New(opts ...Option) *Dialer {
	r := &Dialer{
		strategy: Race{},
		timeout:  2 * time.Second,
		logger:   noopLogger{},
		poolSize: 4,
		dialer:   &net.Dialer{},
		cache:    newDNSCache(0, 0, 0), // disabled by default
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

// lookup performs DNS resolution using the configured strategy.
// Always queries for A and AAAA records (IPv4 and IPv6).
func (r *Dialer) lookup(ctx context.Context, host string) ([]Record, error) {
	queryTypes := []RecordType{TypeA, TypeAAAA}

	type result struct {
		records []Record
		err     error
		qtype   RecordType
	}

	// Buffered channel prevents goroutines from blocking if we return early. We size it
	// to match query count so all goroutines can always send their result without waiting.
	results := make(chan result, len(queryTypes))

	// Query all record types concurrently. For example, if we're querying both A and AAAA,
	// we don't want to sit around waiting for A to complete before starting AAAA. This can
	// significantly reduce total query time, especially when using strategies like Fallback
	// that might need to try multiple resolvers sequentially per type.
	for _, qtype := range queryTypes {
		go func(qt RecordType) {
			records, err := r.strategy.ResolveType(ctx, host, qt, r.resolvers, r.logger)
			results <- result{
				records: records,
				err:     err,
				qtype:   qt,
			}
		}(qtype)
	}

	// Collect all results, even if some queries fail. We take a best-effort
	// approach here: if A records fail but AAAA succeeds, we'll return the AAAA records.
	// Pre-allocate assuming ~4 records per type, just a heuristic based on typical responses.
	allRecords := make([]Record, 0, len(queryTypes)*4)
	for i := 0; i < len(queryTypes); i++ {
		res := <-results
		if res.err != nil {
			// Don't fail the entire lookup if one record type fails. For example, a host
			// might have A records but no AAAA records, and some DNS resolvers report that
			// as an error rather than an empty result.
			r.logger.Debug("query type failed",
				Field{"type", res.qtype.String()},
				Field{"error", res.err.Error()})
			continue
		}
		allRecords = append(allRecords, res.records...)
	}

	return allRecords, nil
}

// lookupIPs extracts IP addresses from DNS records.
func (r *Dialer) lookupIPs(ctx context.Context, host string) ([]net.IP, error) {
	// Fast path: check IP cache first, saves us from parsing strings each time
	if cached := r.cache.getIPs(host); cached != nil {
		r.logger.Debug("IP cache hit",
			Field{"host", host},
			Field{"ips", len(cached)})
		return cached, nil
	}

	r.logger.Debug("IP cache miss",
		Field{"host", host})

	// Cache miss - time to do the actual DNS lookup
	records, err := r.lookup(ctx, host)
	if err != nil {
		return nil, err
	}

	// Extract IPs and find minimum TTL for caching, we need to honor the lowest one
	ips := make([]net.IP, 0, len(records))
	minTTL := uint32(300) // Default 5 minutes if we don't find a TTL, shouldn't happen in practice

	for _, record := range records {
		// Only extract IP addresses from A and AAAA records, ignore CNAME, MX, etc.
		if record.Type == TypeA || record.Type == TypeAAAA {
			ip := net.ParseIP(record.Value)
			if ip != nil {
				ips = append(ips, ip)
				// Track minimum TTL for cache expiration, we use the shortest one to be safe
				if record.TTL < minTTL {
					minTTL = record.TTL
				}
			}
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for %s", host)
	}

	// Cache the IPs for future lookups so we can skip the parsing overhead next time
	r.cache.setIPs(host, ips, time.Duration(minTTL)*time.Second)

	return ips, nil
}

// DialContext implements the net.Dialer.DialContext signature, making it a drop-in replacement
// for any Go code that accepts a custom dialer.
//
// Use with HTTP clients, gRPC connections, or any custom connection pool that needs DNS resolution:
//
//	// HTTP Client
//	client := &http.Client{
//	    Transport: &http.Transport{
//	        DialContext: dialer.DialContext,
//	    },
//	}
//
//	// gRPC
//	conn, err := grpc.Dial("api.example.com:443",
//	    grpc.WithContextDialer(dialer.DialContext),
//	)
//
//	// Custom usage
//	conn, err := dialer.DialContext(ctx, "tcp", "api.github.com:443")
func (r *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {

	var host, portStr string
	var err error

	// if any http or https, strip if
	if strings.HasPrefix(addr, "https://") {
		addr = strings.TrimPrefix(addr, "https://")
	}

	if strings.HasPrefix(addr, "http://") {
		addr = strings.TrimPrefix(addr, "http://")
	}

	if strings.Count(addr, ":") == 1 {
		// Split addr into host and port (standard net package format)
		host, portStr, err = net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q: %w", addr, err)
		}
	}

	// If host is already an IP address, use it directly without DNS lookup. No point
	// in doing DNS resolution for something that's already an IP.
	if ip := net.ParseIP(host); ip != nil {
		return r.dialer.DialContext(ctx, network, addr)
	}

	// Perform DNS lookup using whichever strategy is configured
	ips, err := r.lookupIPs(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", host, err)
	}

	// Filter IPs based on network type
	var filteredIPs []net.IP
	switch network {
	case "tcp4", "udp4":
		// Only use IPv4 addresses, the caller explicitly asked for v4
		for _, ip := range ips {
			if ip.To4() != nil {
				filteredIPs = append(filteredIPs, ip)
			}
		}
	case "tcp6", "udp6":
		// Only use IPv6 addresses, the caller explicitly asked for v6
		for _, ip := range ips {
			if ip.To4() == nil && ip.To16() != nil {
				filteredIPs = append(filteredIPs, ip)
			}
		}
	default:
		// For "tcp" and "udp", use all IPs we got. Try IPv4 first for better compatibility,
		// more things support IPv4 than IPv6 in practice.
		filteredIPs = make([]net.IP, 0, len(ips))
		// Add IPv4 addresses first
		for _, ip := range ips {
			if ip.To4() != nil {
				filteredIPs = append(filteredIPs, ip)
			}
		}
		// Then add IPv6 addresses
		for _, ip := range ips {
			if ip.To4() == nil && ip.To16() != nil {
				filteredIPs = append(filteredIPs, ip)
			}
		}
	}

	if len(filteredIPs) == 0 {
		return nil, fmt.Errorf("no suitable IP addresses found for %s (network: %s)", host, network)
	}

	var lastErr error
	for _, ip := range filteredIPs {
		ipAddr := net.JoinHostPort(ip.String(), portStr)
		conn, err := r.dialer.DialContext(ctx, network, ipAddr)
		if err == nil {
			return conn, nil
		}

		lastErr = err
		r.logger.Debug("connection failed, trying next IP",
			Field{"ip", ip.String()},
			Field{"error", err.Error()})
	}

	return nil, fmt.Errorf("failed to connect to %s: %w", host, lastErr)
}
