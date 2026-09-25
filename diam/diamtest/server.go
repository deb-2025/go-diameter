// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diamtest

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/deb-2025/go-diameter/diam"
	"github.com/deb-2025/go-diameter/diam/dict"
)

// A Server is a Diameter server listening on a system-chosen port on the
// local loopback interface, for use in end-to-end tests.
type Server struct {
	Network  string
	Addr     string
	Listener net.Listener
	TLS      *tls.Config
	Config   *diam.Server
}

// NewServer starts and returns a new Server.
// The caller should call Close when finished, to shut it down.
func NewServer(handler diam.Handler, dp *dict.Parser) *Server {
	return NewServerNetwork("tcp", handler, dp)
}

// NewUnstartedServer returns a new Server but doesn't start it.
//
// After changing its configuration, the caller should call Start or
// StartTLS.
//
// The caller should call Close when finished, to shut it down.
func NewUnstartedServer(handler diam.Handler, dp *dict.Parser) *Server {
	return NewUnstartedServerNetwork("tcp", handler, dp)
}

// NewServerNetwork starts and returns a new Server listening on specified network.
// The caller should call Close when finished, to shut it down.
func NewServerNetwork(network string, handler diam.Handler, dp *dict.Parser) *Server {
	ts := NewUnstartedServerNetwork(network, handler, dp)
	ts.Start()
	return ts
}

// NewUnstartedServerNetwork returns a new Server on the network but doesn't start it.
//
// After changing its configuration, the caller should call Start or
// StartTLS.
//
// The caller should call Close when finished, to shut it down.
func NewUnstartedServerNetwork(network string, handler diam.Handler, dp *dict.Parser) *Server {
	return &Server{
		Listener: newLocalListener(network),
		Config: &diam.Server{
			Network: network,
			Handler: handler,
			Dict:    dp,
		},
	}
}

func newLocalListener(network string) net.Listener {
	if len(network) == 0 {
		network = "tcp"
	}
	l, err := diam.MultistreamListen(network, "127.0.0.1:0")
	if err != nil {
		fmt.Printf("diamtest: failed initial listen on network %s: %v", network, err)
		switch network {
		case "sctp":
			network = "sctp6"
		case "tcp":
			network = "tcp6"
		default:
			panic(fmt.Sprintf("diamtest: failed to listen on network %s: %v", network, err))
		}
		if l, err = diam.MultistreamListen(network, "[::1]:0"); err != nil {
			panic(fmt.Sprintf("diamtest: failed to listen on a port: %v", err))
		}
	}
	return l
}

// Start starts a server from NewUnstartedServer.
func (s *Server) Start() {
	if s.Addr != "" {
		panic("Server already started")
	}
	s.Addr = s.Listener.Addr().String()
	go s.Config.Serve(s.Listener)
}

// StartTLS starts TLS on a server from NewUnstartedServer.
func (s *Server) StartTLS() {
	if s.Addr != "" {
		panic("Server already started")
	}
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		panic(fmt.Sprintf("diamtest: NewTLSServer: %v", err))
	}
	if s.TLS != nil {
		s.TLS = diam.TLSConfigClone(s.TLS)
	} else {
		s.TLS = new(tls.Config)
	}
	/*
		if s.TLS.NextProtos == nil {
			s.TLS.NextProtos = []string{"diameter"}
		}
	*/
	if len(s.TLS.Certificates) == 0 {
		s.TLS.Certificates = []tls.Certificate{cert}
	}
	tlsListener := tls.NewListener(s.Listener, s.TLS)
	s.Listener = tlsListener
	s.Addr = s.Listener.Addr().String()
	go s.Config.Serve(s.Listener)
}

// Close shuts down the server.
func (s *Server) Close() {
	s.Listener.Close()
}

// localhostCert is a PEM-encoded TLS cert with SAN IPs
// "127.0.0.1" and "[::1]", expiring at the last second of 2049 (the end
// of ASN.1 time).
// generated from src/crypto/tls:
// go run generate_cert.go  --rsa-bits 512 --host 127.0.0.1,::1,example.com --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
var localhostCert = []byte(``)

var localhostKey = []byte(``)
