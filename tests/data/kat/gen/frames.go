package main

import (
	"bytes"
	"context"
	stdtls "crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"sync"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2raywebsocket"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

// flight collects what a reference client writes once `send` has run
// against one end of a pipe. Nothing answers it: these are the client's
// first flights, which every reference here sends without waiting.
func flight(send func(net.Conn)) []byte {
	clientEnd, serverEnd := net.Pipe()
	var wire bytes.Buffer
	var done sync.WaitGroup
	done.Add(1)
	go func() {
		defer done.Done()
		_, _ = io.Copy(&wire, serverEnd)
	}()
	send(clientEnd)
	clientEnd.Close()
	done.Wait()
	return wire.Bytes()
}

var (
	frameTarget  = M.ParseSocksaddr("example.com:443")
	frameTarget2 = M.ParseSocksaddr("192.0.2.7:53")
)

const (
	frameUserID = "b831381d-6324-4d53-ad4f-8cda48b30811"
	framePSK    = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	frameTime   = 1760000000
)

func frameObject(target M.Socksaddr, payload, wire []byte) object {
	return object{"target": target.String(), "payload": h(payload), "wire": h(wire)}
}

// Client flights from the sing references, for shoes' servers to decode:
// each must yield the target and the payload the reference was given.
func genFrames() {
	payload := []byte("first flight payload")

	// Both stamp their requests with the time, which the servers check, so
	// the flights are made at a fixed one that the tests pin.
	at := func() time.Time { return time.Unix(frameTime, 0) }
	ss, err := shadowaead_2022.NewWithPassword("2022-blake3-aes-256-gcm", framePSK, at)
	must(err)
	ssWire := flight(func(conn net.Conn) {
		_, err := ss.DialEarlyConn(conn, frameTarget).Write(payload)
		must(err)
	})

	vmessTCP, err := vmess.NewClient(frameUserID, "aes-128-gcm", 0, vmess.ClientWithTimeFunc(at))
	must(err)
	vmessWire := flight(func(conn net.Conn) {
		_, err := vmessTCP.DialEarlyConn(conn, frameTarget).Write(payload)
		must(err)
	})
	vmessPadded, err := vmess.NewClient(frameUserID, "aes-128-gcm", 0, vmess.ClientWithGlobalPadding(), vmess.ClientWithTimeFunc(at))
	must(err)
	vmessUDPWire := flight(func(conn net.Conn) {
		_, err := vmessPadded.DialEarlyPacketConn(conn, frameTarget2).Write(payload)
		must(err)
	})

	vlessClient, err := vless.NewClient(frameUserID, "", logger.NOP())
	must(err)
	vlessWire := flight(func(conn net.Conn) {
		early, err := vlessClient.DialEarlyConn(conn, frameTarget)
		must(err)
		_, err = early.Write(payload)
		must(err)
	})
	second := []byte("second packet")
	xudpWire := flight(func(conn net.Conn) {
		packets, err := vlessClient.DialEarlyXUDPPacketConn(conn, frameTarget2)
		must(err)
		_, err = packets.WriteTo(payload, frameTarget2.UDPAddr())
		must(err)
		_, err = packets.WriteTo(second, frameTarget2.UDPAddr())
		must(err)
	})

	psk, err := base64.StdEncoding.DecodeString(framePSK)
	must(err)
	write("frames-sing", "github.com/sagernet/sing-shadowsocks v0.2.9 shadowaead_2022; github.com/sagernet/sing-vmess v0.2.8 (vmess, vless, xudp): client first flights", object{
		"unix_time":        frameTime,
		"user_id":          frameUserID,
		"psk":              h(psk),
		"ss2022_tcp":       frameObject(frameTarget, payload, ssWire),
		"vmess_tcp":        frameObject(frameTarget, payload, vmessWire),
		"vmess_udp_padded": frameObject(frameTarget2, payload, vmessUDPWire),
		"vless_tcp":        frameObject(frameTarget, payload, vlessWire),
		"xudp": object{
			"target":  frameTarget2.String(),
			"packets": []string{h(payload), h(second)},
			"wire":    h(xudpWire),
		},
	})
}

// flightWithin is flight for a client that may wait for an answer that
// never comes: what it wrote by the deadline is the flight.
func flightWithin(deadline time.Duration, send func(net.Conn)) []byte {
	clientEnd, serverEnd := net.Pipe()
	var wire bytes.Buffer
	var mu sync.Mutex
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buf := make([]byte, 4096)
		for {
			n, err := serverEnd.Read(buf)
			mu.Lock()
			wire.Write(buf[:n])
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	go send(clientEnd)
	time.Sleep(deadline)
	clientEnd.Close()
	serverEnd.Close()
	<-drained
	mu.Lock()
	defer mu.Unlock()
	return append([]byte(nil), wire.Bytes()...)
}

// pipeDialer hands out one prepared connection.
type pipeDialer struct{ conn net.Conn }

func (d pipeDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}

func (d pipeDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

// innerClientHello is the first record a TLS client sends: what Vision
// recognises and long-pads.
func innerClientHello() []byte {
	return flightWithin(200*time.Millisecond, func(conn net.Conn) {
		_ = stdtls.Client(conn, &stdtls.Config{ServerName: "inner.example.com"}).Handshake()
	})
}

// Flights inside TLS (AnyTLS, Vision) and over sing-box's WebSocket.
func genFramesTLS() {
	payload := []byte("first flight payload")
	const anytlsPassword = "anytls password"

	anytlsWire := flightWithin(500*time.Millisecond, func(conn net.Conn) {
		client, err := anytls.NewClient(context.Background(), anytls.ClientConfig{
			Password: anytlsPassword,
			DialOut:  func(context.Context) (net.Conn, error) { return conn, nil },
			Logger:   logger.NOP(),
		})
		must(err)
		stream, err := client.CreateProxy(context.Background(), frameTarget)
		must(err)
		_, _ = stream.Write(payload)
	})

	vlessClient, err := vless.NewClient(frameUserID, "", logger.NOP())
	must(err)
	wsWire := flightWithin(500*time.Millisecond, func(conn net.Conn) {
		transport, err := v2raywebsocket.NewClient(context.Background(), pipeDialer{conn}, M.ParseSocksaddr("ws.example.com:80"), option.V2RayWebsocketOptions{
			Path:         "/ws",
			MaxEarlyData: 2048,
		}, nil)
		must(err)
		ws, err := transport.DialContext(context.Background())
		must(err)
		early, err := vlessClient.DialEarlyConn(ws, frameTarget)
		must(err)
		_, _ = early.Write(payload)
	})

	// Vision reads Go's TLS state, so it runs over a real TLS connection;
	// the flight is the plaintext the TLS server reads.
	hello := innerClientHello()
	visionClient, err := vless.NewClient(frameUserID, vless.FlowVision, logger.NOP())
	must(err)
	clientEnd, serverEnd := net.Pipe()
	server := stdtls.Server(serverEnd, &stdtls.Config{
		Certificates: []stdtls.Certificate{selfSigned("vision.example.com")},
		MinVersion:   stdtls.VersionTLS13,
	})
	var vision bytes.Buffer
	var mu sync.Mutex
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := server.Read(buf)
			mu.Lock()
			vision.Write(buf[:n])
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	go func() {
		tlsConn := stdtls.Client(clientEnd, &stdtls.Config{ServerName: "vision.example.com", InsecureSkipVerify: true, MinVersion: stdtls.VersionTLS13})
		must(tlsConn.Handshake())
		conn, err := visionClient.DialEarlyConn(tlsConn, frameTarget)
		must(err)
		_, _ = conn.Write(hello)
	}()
	time.Sleep(time.Second)
	clientEnd.Close()
	mu.Lock()
	visionWire := append([]byte(nil), vision.Bytes()...)
	mu.Unlock()

	write("frames-sing-tls", "github.com/anytls/sing-anytls v0.0.11 CreateProxy; github.com/sagernet/sing-box v1.14.3 transport/v2raywebsocket (max_early_data 2048, path mode) carrying sing-vmess vless; sing-vmess vless xtls-rprx-vision over Go crypto/tls (the plaintext the TLS server read)", object{
		"user_id":         frameUserID,
		"anytls_password": anytlsPassword,
		"anytls":          frameObject(frameTarget, payload, anytlsWire),
		"websocket_vless": frameObject(frameTarget, payload, wsWire),
		"vision":          frameObject(frameTarget, hello, visionWire),
	})
}
