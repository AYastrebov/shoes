package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	shadowtls "github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// records splits a byte stream into TLS records, header included.
func records(stream []byte) []string {
	var out []string
	for len(stream) >= 5 {
		n := 5 + int(binary.BigEndian.Uint16(stream[3:5]))
		if n > len(stream) {
			panic("a TLS record runs past the end of the capture")
		}
		out = append(out, h(stream[:n]))
		stream = stream[n:]
	}
	if len(stream) != 0 {
		panic("a partial TLS record header at the end of the capture")
	}
	return out
}

// tap records what crosses a connection in each direction.
type tap struct {
	net.Conn
	mu       sync.Mutex
	sent     bytes.Buffer
	received bytes.Buffer
}

func (t *tap) Write(p []byte) (int, error) {
	t.mu.Lock()
	t.sent.Write(p)
	t.mu.Unlock()
	return t.Conn.Write(p)
}

func (t *tap) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	t.mu.Lock()
	t.received.Write(p[:n])
	t.mu.Unlock()
	return n, err
}

func selfSigned(name string) stdtls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	must(err)
	return stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type echoHandler struct{ reply []byte }

func (e echoHandler) NewConnectionEx(_ context.Context, conn net.Conn, _ M.Socksaddr, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	defer conn.Close()
	buf := make([]byte, 64)
	if _, err := conn.Read(buf); err != nil {
		return
	}
	_, _ = conn.Write(e.reply)
	_, _ = io.Copy(io.Discard, conn)
}

// ShadowTLS v3: a sing-shadowtls client and server, the server fronting a Go
// TLS 1.3 server, with both directions of the client's connection recorded.
// The HMACs are internal to sing-shadowtls, so they are checked as they
// cross the wire: the ClientHello's session id, the server's tagged
// handshake records, and the data frames each way.
func genShadowTLS() {
	const password = "shadowtls password"
	clientMessage, serverMessage := []byte("data from the client"), []byte("reply from the server")
	ctx := context.Background()

	handshake, err := stdtls.Listen("tcp", "127.0.0.1:0", &stdtls.Config{
		Certificates: []stdtls.Certificate{selfSigned("www.example.com")},
		MinVersion:   stdtls.VersionTLS13,
	})
	must(err)
	defer handshake.Close()
	go func() {
		for {
			conn, err := handshake.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, conn); conn.Close() }()
		}
	}()

	service, err := shadowtls.NewService(shadowtls.ServiceConfig{
		Version: 3,
		Users:   []shadowtls.User{{Name: "user", Password: password}},
		Handshake: shadowtls.HandshakeConfig{
			Server: M.ParseSocksaddr(handshake.Addr().String()),
			Dialer: N.SystemDialer,
		},
		Handler: echoHandler{reply: serverMessage},
		Logger:  logger.NOP(),
	})
	must(err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		_ = service.NewConnection(ctx, conn, M.Socksaddr{}, M.Socksaddr{}, nil)
	}()

	raw, err := net.Dial("tcp", listener.Addr().String())
	must(err)
	wire := &tap{Conn: raw}
	client, err := shadowtls.NewClient(shadowtls.ClientConfig{
		Version:  3,
		Password: password,
		Server:   M.ParseSocksaddr(listener.Addr().String()),
		Dialer:   N.SystemDialer,
		TLSHandshake: shadowtls.DefaultTLSHandshakeFunc(password, &stdtls.Config{
			ServerName:         "www.example.com",
			InsecureSkipVerify: true,
			MinVersion:         stdtls.VersionTLS13,
		}),
		Logger: logger.NOP(),
	})
	must(err)
	conn, err := client.DialContextConn(ctx, wire)
	must(err)
	_, err = conn.Write(clientMessage)
	must(err)
	reply := make([]byte, len(serverMessage))
	_, err = io.ReadFull(conn, reply)
	must(err)
	if !bytes.Equal(reply, serverMessage) {
		panic("the ShadowTLS reply came back changed")
	}
	conn.Close()

	wire.mu.Lock()
	defer wire.mu.Unlock()
	write("shadowtls", "github.com/sagernet/sing-shadowtls v3: NewClient with DefaultTLSHandshakeFunc, NewService; Go crypto/tls as the handshake server", object{
		"password":         password,
		"client_message":   h(clientMessage),
		"server_message":   h(serverMessage),
		"client_to_server": records(wire.sent.Bytes()),
		"server_to_client": records(wire.received.Bytes()),
	})
}

// REALITY: the ClientHello sing-box's client sends for a key pair made here.
// Its client key share is ephemeral and never leaves uTLS, so the vector is
// checked from the server side: the recorded private key must open the
// SessionId it sealed.
func genReality() {
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	must(err)
	const shortID = "0123456789abcdef"
	const serverName = "www.example.com"
	config, err := sbtls.NewRealityClient(context.Background(), logger.NOP(), "127.0.0.1:443", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: base64.RawURLEncoding.EncodeToString(serverKey.PublicKey().Bytes()),
			ShortID:   shortID,
		},
	})
	must(err)

	clientSide, serverSide := net.Pipe()
	reality := config.(*sbtls.RealityClientConfig)
	go func() { _, _ = reality.ClientHandshake(context.Background(), clientSide) }()
	header := make([]byte, 5)
	_, err = io.ReadFull(serverSide, header)
	must(err)
	body := make([]byte, binary.BigEndian.Uint16(header[3:5]))
	_, err = io.ReadFull(serverSide, body)
	must(err)
	serverSide.Close()

	write("reality", "github.com/sagernet/sing-box v1.14.3 common/tls: NewRealityClient (uTLS chrome), ClientHandshake", object{
		"server_private_key": h(serverKey.Bytes()),
		"short_id":           shortID,
		"server_name":        serverName,
		"client_hello":       h(append(header, body...)),
	})
}
