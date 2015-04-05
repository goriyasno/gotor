// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/tvdw/cgolock"
	"log"
	"os"
	"runtime"
)

import _ "net/http/pprof"
import _ "expvar"

var internal = flag.Bool("internal", true, "make a few OR/OPs locally and build a circuit")
var repl = flag.Bool("repl", false, "give a little prompt-like thing")
var torrc = flag.String("f", "torrc", "torrc filename")
var ors = [5]*ORCtx{}

func main() {
	cgolock.Init(runtime.NumCPU())
	runtime.GOMAXPROCS(runtime.NumCPU())
	SetupRand()
	SeedCellBuf()

	endChan, err := runChain()
	if err != nil {
		fmt.Println(err)
		return
	}

	socksMain(ors[0])
	_ = <-endChan
	fmt.Println("exiting")
}

func runChain() (chan int, error) {
	badChan := make(chan int)
	//ors, err := mkOrs(numOrs)
	err := mkOrs()
	if err != nil {
		return badChan, err
	}
	err = runOrs(badChan)
	if err != nil {
		return badChan, err
	}
	err = chainOrs()
	if err != nil {
		return badChan, err
	}
	return badChan, nil
}

func mkOrs() error {
	pwd, err := os.Getwd()
	if err != nil {
		return errors.New("couldn't get pwd")
	}
	baseDir := pwd + "/gotordemo/"
	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		err = os.Mkdir(baseDir, 0755)
		if err != nil {
			panic(err)
		}
	}

	for i := range ors {
		log.Println("making OR number ", i)
		config := Config{
			IsPublicServer:    false,
			DataDirectory:     fmt.Sprintf("%s/tor%d", baseDir, i),
			ORPort:            uint16(9090 + i),
			Platform:          "Tor 0.2.6.2-alpha on Go",
			BandwidthAvg:      0,
			BandwidthBurst:    0,
			BandwidthObserved: 0,
		}

		rule := ExitRule{}
		rule.Action = true
		config.ExitPolicy.Rules = append(config.ExitPolicy.Rules, rule)

		or, err := NewOR(&config)
		if err != nil {
			return err
		}
		ors[i] = or
	}

	return nil
}

func runOrs(badChan chan int) error {
	for _, or := range ors {
		or := or
		go func() {
			or.Run()
			badChan <- 1
		}()
	}

	go func() {
		select {
		case <-badChan:
			log.Panicln("Somehow a main.go goroutine we spawned managed to finish, which is not good")
		}
	}()
	return nil
}

func chainOrs() error {
	extendCircId := CircuitID(0) // first time around, this is zero
	for i := range ors {
		if i+1 > len(ors)-1 {
			break
		}
		// we'll ask ors[0] to connect and CREATE to ors[1], EXTEND to the rest
		doneChan, err := ors[0].RequestProxyCircuit(CircuitID(extendCircId),
			[]byte{0, 0, 0, 0, 35, byte(131 + i)}, ors[i+1].serverTlsCtx.Fingerprint, ors[i+1].ntorPublic)
		if err != nil {
			return err
		}
		extendCircId = <-doneChan
		fmt.Println("extended to", extendCircId)
	}
	return nil
}
