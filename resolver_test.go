// Copyright 2025 Bruno Schaatsbergen. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsdialer

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func TestDialer_DialContext(t *testing.T) {
	// Create local HTTP test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from test server"))
	}))
	defer server.Close()

	dialer := New(
		WithResolvers("8.8.8.8:53"),
		WithStrategy(Race{}),
	)

	ctx := context.Background()
	conn, err := dialer.DialContext(ctx, "tcp", server.URL)

	assert.NoError(t, err)

	if conn != nil {
		defer conn.Close()
		assert.Equal(t, "tcp", conn.LocalAddr().Network())

	}

}

func TestDialer_DialContext_HTTPClient(t *testing.T) {
	// Create local HTTP test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from test server"))
	}))
	defer server.Close()

	dialer := New(
		WithResolvers("8.8.8.8:53"),
		WithStrategy(Race{}),
	)

	// Create HTTP client using our dialer
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
		},
	}

	resp, err := client.Get(server.URL)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestDialer_DialContext_gRPC(t *testing.T) {
	// Create a simple gRPC server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer listener.Close()

	server := grpc.NewServer()

	// Start the server in a goroutine
	go func() {
		server.Serve(listener)
	}()
	defer server.Stop()

	dialer := New(
		WithResolvers("8.8.8.8:53"),
		WithStrategy(Race{}),
	)

	// Create gRPC connection using our custom dialer
	conn, err := grpc.NewClient(
		listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", addr)
		}),
	)

	assert.NoError(t, err)
	assert.NotNil(t, conn)

	// Test that the connection is actually working
	// Since we don't have any services registered, we expect an unimplemented error
	// which proves the connection is working
	ctx := context.Background()
	err = conn.Invoke(ctx, "/test.Service/Method", nil, nil)

	// Should get "unimplemented" status, which means connection worked
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())

	conn.Close()
}
