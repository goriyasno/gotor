// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/tvdw/gotor/tordir"
	"github.com/tvdw/openssl"
	"golang.org/x/crypto/curve25519"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"
)

type Fingerprint [20]byte

func (fp Fingerprint) String() string {
	return fmt.Sprintf("%X", fp[:])
}

type ORCtx struct {
	// For convenience we use net.Listen instead of delegating to openssl itself.
	// This allows us to very easily swap certificates as our listening socket doesn't reference a tls context
	listener net.Listener
	config   *Config

	// Hold Fingerprint to OnionConnection mappings
	authenticatedConnections map[Fingerprint]*OnionConnection
	authConnLock             sync.Mutex

	descriptor tordir.Descriptor

	identityKey, onionKey   openssl.PrivateKey
	ntorPrivate, ntorPublic [32]byte

	clientTlsCtx, serverTlsCtx *TorTLS
	tlsLock                    sync.Mutex
}

func NewOR(torConf *Config) (*ORCtx, error) {
	connStr := fmt.Sprintf(":%d", torConf.ORPort)
	listener, err := net.Listen("tcp", connStr)
	if err != nil {
		return nil, err
	}

	ctx := &ORCtx{
		listener:                 listener,
		authenticatedConnections: make(map[Fingerprint]*OnionConnection),
		config: torConf,
	}

	if _, err := os.Stat(torConf.DataDirectory + "/keys/secret_id_key"); os.IsNotExist(err) {
		Log(LOG_INFO, "Generating new keys")
		err = os.Mkdir(torConf.DataDirectory, 0755)
		if err != nil {
			panic(err)
		}
		err = os.Mkdir(torConf.DataDirectory+"/keys", 0700)
		if err != nil {
			panic(err)
		}

		{
			newIDKey, err := openssl.GenerateRSAKeyWithExponent(1024, 65537)
			if err != nil {
				return nil, err
			}
			newIDKeyPEM, err := newIDKey.MarshalPKCS1PrivateKeyPEM()
			if err != nil {
				return nil, err
			}
			if err := ioutil.WriteFile(torConf.DataDirectory+"/keys/secret_id_key", newIDKeyPEM, 0600); err != nil {
				return nil, err
			}
		}

		{
			newOnionKey, err := openssl.GenerateRSAKeyWithExponent(1024, 65537)
			if err != nil {
				return nil, err
			}
			newOnionKeyPEM, err := newOnionKey.MarshalPKCS1PrivateKeyPEM()
			if err != nil {
				return nil, err
			}
			if err := ioutil.WriteFile(torConf.DataDirectory+"/keys/secret_onion_key", newOnionKeyPEM, 0600); err != nil {
				return nil, err
			}
		}

		{
			var curveDataPriv [32]byte
			var curveDataPub [32]byte
			CRandBytes(curveDataPriv[0:32])
			curveDataPriv[0] &= 248
			curveDataPriv[31] &= 127
			curveDataPriv[31] |= 64
			curve25519.ScalarBaseMult(&curveDataPub, &curveDataPriv)

			var buf bytes.Buffer
			buf.WriteString("== c25519v1: onion ==")
			for i := buf.Len(); i < 32; i++ {
				buf.Write([]byte{0})
			}
			buf.Write(curveDataPriv[:])
			buf.Write(curveDataPub[:])
			if err := ioutil.WriteFile(torConf.DataDirectory+"/keys/secret_onion_key_ntor", buf.Bytes(), 0600); err != nil {
				return nil, err
			}
		}
	}

	{
		identityPem, err := ioutil.ReadFile(torConf.DataDirectory + "/keys/secret_id_key")
		if err != nil {
			return nil, err
		}
		identityPk, err := openssl.LoadPrivateKeyFromPEM(identityPem)
		if err != nil {
			return nil, err
		}
		ctx.identityKey = identityPk
	}
	{
		onionPem, err := ioutil.ReadFile(torConf.DataDirectory + "/keys/secret_onion_key")
		if err != nil {
			return nil, err
		}
		onionPk, err := openssl.LoadPrivateKeyFromPEM(onionPem)
		if err != nil {
			return nil, err
		}
		ctx.onionKey = onionPk
	}
	{
		ntorData, err := ioutil.ReadFile(torConf.DataDirectory + "/keys/secret_onion_key_ntor")
		if err != nil {
			return nil, err
		}
		if len(ntorData) != 96 {
			return nil, errors.New("ntor data corrupt")
		}
		copy(ctx.ntorPrivate[:], ntorData[32:64])
		copy(ctx.ntorPublic[:], ntorData[64:96])
	}

	if err := SetupTLS(ctx); err != nil {
		return nil, err
	}

	ctx.descriptor.UptimeStart = time.Now()

	return ctx, nil
}

func (or *ORCtx) RotateKeys() error {
	return SetupTLS(or)
}

func (or *ORCtx) UpdateDescriptor() {
	d := &or.descriptor
	d.Nickname = or.config.Nickname
	d.Contact = or.config.Contact
	d.Platform = or.config.Platform
	d.Address = net.ParseIP(or.config.Address)
	d.ORPort = or.config.ORPort
	d.OnionKey = or.onionKey
	d.SigningKey = or.identityKey
	d.BandwidthAvg = or.config.BandwidthAvg
	d.BandwidthBurst = or.config.BandwidthBurst
	d.BandwidthObserved = or.config.BandwidthObserved
	d.NTORKey = or.ntorPublic[:]
	d.Family = or.config.Family
	policy, err := or.config.ExitPolicy.Describe()
	if err != nil {
		Log(LOG_WARN, "%s", err)
		return
	}
	d.ExitPolicy = policy

	signed, err := d.SignedDescriptor()
	if err != nil {
		Log(LOG_WARN, "%s", err)
		return
	}

	Log(LOG_DEBUG, "%s", signed)
}

func (or *ORCtx) PublishDescriptor() error {
	if or.config.IsPublicServer {
		or.UpdateDescriptor()
		authorities := []string{"171.25.193.9:443", "86.59.21.38:80", "208.83.223.34:443", "199.254.238.52:80", "194.109.206.212:80", "131.188.40.189:80", "128.31.0.34:9131", "193.23.244.244:80", "154.35.32.5:80"}
		for _, auth := range authorities {
			if err := or.descriptor.Publish(auth); err != nil {
				Log(LOG_NOTICE, "%s", err) // XXX
			}
		}
	}
	return nil
}

func (or *ORCtx) Run() {
	for {
		conn, err := or.listener.Accept()
		if err != nil {
			Log(LOG_WARN, "%s", err)
			continue
		}

		// Handshake, etc
		go func() {
			defer conn.Close()
			Log(LOG_DEBUG, "%s says hi", conn.RemoteAddr())
			HandleORConnServer(or, conn)
		}()
	}
}

func (or *ORCtx) RegisterConnection(fp Fingerprint, conn *OnionConnection) error {
	or.authConnLock.Lock()
	defer or.authConnLock.Unlock()

	_, ok := or.authenticatedConnections[fp]
	if ok {
		return errors.New("we already have this fingerprint registered")
	}

	Log(LOG_INFO, "registering a connection for fp %s", fp)
	or.authenticatedConnections[fp] = conn

	return nil
}

func (or *ORCtx) EndConnection(fp Fingerprint, conn *OnionConnection) error {
	or.authConnLock.Lock()
	defer or.authConnLock.Unlock()

	cur, ok := or.authenticatedConnections[fp]
	if !ok {
		return nil // Not an error
	}

	if cur != conn {
		return errors.New("mismatch: another connection is registered")
	}

	delete(or.authenticatedConnections, fp)

	return nil
}

func (or *ORCtx) RequestCircuit(req *CircuitRequest) error {
	or.authConnLock.Lock()
	defer or.authConnLock.Unlock()

	fp := req.connHint.GetFingerprint()
	if fp != nil {
		// XXX This needs to be a lot smarter (check IP addresses, etc)
		conn, ok := or.authenticatedConnections[*fp]
		if ok {
			conn.circuitReadQueue <- req
			return nil
		}
	}

	//todo check aborted lock?
	if req.extendCircId != 0 {
		fmt.Println("looking for", req.extendCircId)
		for _, conn := range or.authenticatedConnections {
			_, ok := conn.proxyCircuits[req.extendCircId]
			if ok {
				conn.circuitReadQueue <- req
				return nil
			}
		}
		return errors.New("Can't extend from nonexistent circuit")
	}

	// Try and dial
	go func() {
		addresses := req.connHint.GetAddresses()
		for _, addr := range addresses {
			// Allow aborting connection attempts
			req.handshakeState.lock.Lock()
			aborted := req.handshakeState.aborted
			req.handshakeState.lock.Unlock()
			if aborted {
				Log(LOG_INFO, "Aborting connection attempt")
				return
			}

			// Now connect
			Log(LOG_INFO, "connecting to %s", addr)
			dialer := net.Dialer{Timeout: 5 * time.Second}
			conn, err := dialer.Dial("tcp", addr)
			if err != nil {
				Log(LOG_INFO, "%s", err)
				continue // Next address
			}

			defer conn.Close()
			HandleORConnClient(or, conn, req)
			return
		}

		// Bad luck but it does need to be reported
		req.successQueue <- &CircuitDestroyed{
			id:     req.localID,
			reason: 6, //CONNECTFAILED
			//truncate: true,
		}
	}()

	return nil
}

func (or *ORCtx) RequestProxyCircuit(extCirc CircuitID, theirAddress []byte, theirFingerprint Fingerprint, theirPublic [32]byte) (chan CircuitID, error) {
	doneChan := make(chan CircuitID)

	var curveDataPriv [32]byte
	var curveDataPub [32]byte
	CRandBytes(curveDataPriv[0:32])
	curveDataPriv[0] &= 248
	curveDataPriv[31] &= 127
	curveDataPriv[31] |= 64
	curve25519.ScalarBaseMult(&curveDataPub, &curveDataPriv)

	hdata, err := NtorClientPayload(theirFingerprint, theirPublic, curveDataPub)
	if err != nil {
		return nil, err
	}
	err = or.RequestCircuit(&CircuitRequest{
		connHint: ConnectionHint{
			address: [][]byte{theirAddress},
		},
		handshakeState: &CircuitHandshakeState{
			keys:        [2][32]byte{curveDataPriv, curveDataPub},
			fingerprint: theirFingerprint,
			onionPublic: theirPublic,
			whenDone:    doneChan,
		},
		newHandshake:   true,
		handshakeType:  uint16(HANDSHAKE_NTOR),
		handshakeData:  hdata[:],
		weAreInitiator: true,
		extendCircId:   extCirc,
	})
	return doneChan, err
}

func (or *ORCtx) DestroyAllProxyCircuits() {
	for _, conn := range or.authenticatedConnections {
		for _, pc := range conn.proxyCircuits {
			fmt.Println("queueing destroy for circuit", pc.id)
			conn.writeQueue <- NewCell(conn.negotiatedVersion, pc.id, CMD_DESTROY, []byte{0}).Bytes()
		}
	}
}

func (or *ORCtx) RandomConnection() (*OnionConnection, error) {
	for _, conn := range or.authenticatedConnections {
		return conn, nil
	}
	return nil, errors.New("no connections")
}

func (or *ORCtx) ListConns() {
	for fp, conn := range or.authenticatedConnections {
		for pc, _ := range conn.proxyCircuits {
			fmt.Printf("conn %s has pc %d\n", fp.String(), pc)
		}
	}
}

// this thing encrypts a relay cell down a proxy circuit
// copy paste mostly from sendrelaycell
func (c *OnionConnection) sendProxyCell(pc *ProxyCircuit, stream StreamID, command RelayCommand, data []byte) ActionableError {
	if len(data) > MAX_RELAY_LEN {
		panic("Somehow we're trying to send a massive cell")
	}

	cell := NewCell(c.negotiatedVersion, pc.id, CMD_RELAY, nil)
	buf := cell.Data()

	// The rest will be crypto'd
	buf[0] = byte(command)
	buf[1] = 0 // recognized
	buf[2] = 0
	BigEndian.PutUint16(buf[3:5], uint16(stream))

	// placeholder for digest

	if data != nil && len(data) != 0 {
		BigEndian.PutUint16(buf[9:11], uint16(len(data)))
		copy(buf[11:], data)
	}

	pc.forwardChain[len(pc.forwardChain)-1].digest.Write(buf)
	digest := pc.forwardChain[len(pc.forwardChain)-1].digest.Sum(nil)
	buf[5] = digest[0]
	buf[6] = digest[1]
	buf[7] = digest[2]
	buf[8] = digest[3]

	// Now AES it

	for i := len(pc.forwardChain) - 1; i >= 0; i-- {
	    fmt.Println("crypting with", pc.forwardChain[i])
		pc.forwardChain[i].cipher.Crypt(buf, buf)
	}

	c.writeQueue <- cell.Bytes() // XXX this could deadlock

	return nil
}

func NewStreamID() StreamID {
	return StreamID(rand.Intn(256*255) + 1)
}
