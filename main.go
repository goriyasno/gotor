// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"github.com/tvdw/cgolock"
	"log"
	"os"
	"runtime"
)

import _ "net/http/pprof"
import _ "expvar"

func main() {
	cgolock.Init(runtime.NumCPU())
	runtime.GOMAXPROCS(runtime.NumCPU())
	SetupRand()
	SeedCellBuf()

	///////////////////////
	torConfig1 := Config{
		IsPublicServer:    false,
		DataDirectory:     "/home/landers/code/gocode/bin/.gotor",
		ORPort:            9090,
		Platform:          "Tor 0.2.6.2-alpha on Go",
		BandwidthAvg:      0,
		BandwidthBurst:    0,
		BandwidthObserved: 0,
	}
	if err := torConfig1.ReadFile(os.Args[1]); err != nil {
		log.Panicln(err)
	}

	torConfig2 := Config{
		IsPublicServer:    false,
		DataDirectory:     "/home/landers/code/gocode/bin/.gotor2",
		ORPort:            9091,
		Platform:          "Tor 0.2.6.2-alpha on Go",
		BandwidthAvg:      0,
		BandwidthBurst:    0,
		BandwidthObserved: 0,
	}
	if err := torConfig2.ReadFile(os.Args[1]); err != nil {
		log.Panicln(err)
	}
	/////////////////////////

	or1, err := NewOR(&torConfig1)
	if err != nil {
		log.Panicln(err)
	}

	or2, err := NewOR(&torConfig2)
	if err != nil {
		log.Panicln(err)
	}

	go func() {
		hdata, err := NtorClientPayload(or2.serverTlsCtx.Fingerprint, or2.ntorPublic, or1.ntorPublic)
		if err != nil {
			log.Panicln(err)
		}
		cr := CircuitRequest{
			localID: 5,
			connHint: ConnectionHint{
				address: [][]byte{[]byte{127, 0, 0, 1, 35, 131}},
			},
			handshakeState: &CircuitHandshakeState{
				keys:        [2][32]byte{or1.ntorPrivate, or1.ntorPublic},
				fingerprint: or2.serverTlsCtx.Fingerprint,
				onionPublic: or2.ntorPublic,
			},
			newHandshake:   true,
			handshakeType:  uint16(HANDSHAKE_NTOR),
			handshakeData:  hdata[:],
			weAreInitiator: true,
		}
		log.Println(cr)
		or1.RequestCircuit(&cr)
	}()

	anythingFinished := make(chan int)
	go func() {
		or1.Run()
		anythingFinished <- 1
	}()
	go func() {
		or2.Run()
		anythingFinished <- 1
	}()

	select {
	case <-anythingFinished:
		log.Panicln("Somehow a main.go goroutine we spawned managed to finish, which is not good")
	}
}
