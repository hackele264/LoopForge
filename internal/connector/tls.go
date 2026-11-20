package connector

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"agentflow/internal/domain"
)

// tlsClients caches one client per distinct TLS setting, so pinned
// connections keep their keep-alive pool across calls.
type tlsClients struct {
	mu      sync.Mutex
	clients map[string]*http.Client
}

// clientFor returns the shared client, or for a connection with its own TLS
// settings a client that trusts its CA bundle and checks its pinned
// certificate.
func (x *Executor) clientFor(conn *domain.Connection) (*http.Client, error) {
	if conn == nil || (conn.TLSCertSHA256 == "" && conn.TLSCAPEM == "") {
		return x.client, nil
	}
	sum := sha256.Sum256([]byte(conn.TLSCertSHA256 + "\x00" + conn.TLSCAPEM))
	key := hex.EncodeToString(sum[:])
	x.tls.mu.Lock()
	defer x.tls.mu.Unlock()
	if c, ok := x.tls.clients[key]; ok {
		return c, nil
	}
	cfg, err := connectionTLSConfig(conn.TLSCertSHA256, conn.TLSCAPEM)
	if err != nil {
		return nil, fmt.Errorf("连接 %s 的 TLS 设置无效：%w", conn.Name, err)
	}
	var transport *http.Transport
	if base, ok := x.client.Transport.(*http.Transport); ok && base != nil {
		transport = base.Clone()
	} else {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	transport.TLSClientConfig = cfg
	c := *x.client
	c.Transport = transport
	if x.tls.clients == nil {
		x.tls.clients = map[string]*http.Client{}
	}
	x.tls.clients[key] = &c
	return &c, nil
}

// connectionTLSConfig trusts caPEM when set and, when pin is set, accepts
// only a server whose leaf certificate hashes to pin. With a pin and no CA
// the chain is not verified: the pin is the trust decision, as for a
// self-signed certificate.
func connectionTLSConfig(pin, caPEM string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, errors.New("CA 证书无法解析")
		}
		cfg.RootCAs = pool
	}
	if pin == "" {
		return cfg, nil
	}
	want, err := hex.DecodeString(pin)
	if err != nil || len(want) != sha256.Size {
		return nil, errors.New("证书指纹必须是 64 位十六进制")
	}
	cfg.InsecureSkipVerify = caPEM == ""
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("服务端没有出示证书")
		}
		got := sha256.Sum256(cs.PeerCertificates[0].Raw)
		if hex.EncodeToString(got[:]) != hex.EncodeToString(want) {
			return fmt.Errorf("服务端证书指纹 %s 与连接里固定的不一致", hex.EncodeToString(got[:]))
		}
		return nil
	}
	return cfg, nil
}
