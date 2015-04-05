// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/joelanders/zoossh"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var datadir string
var line string
var err error
var reader = bufio.NewReader(os.Stdin)

func Repl() {
	anythingFinished := make(chan int)
	datadir, err := os.Getwd()
	if err != nil {
		fmt.Println("couldn't get pwd")
		log.Panicln(err)
	}
	config := Config{
		Nickname:          "joetest",
		IsPublicServer:    false,
		DataDirectory:     datadir,
		ORPort:            uint16(9090),
		Platform:          "Tor 0.2.6.2-alpha on Go",
		BandwidthAvg:      0,
		BandwidthBurst:    0,
		BandwidthObserved: 0,
	}

	or, err := NewOR(&config)
	if err != nil {
		log.Panicln(err)
	}

	go func() {
		or.Run()
		anythingFinished <- 1
	}()

	consensus, err := getConsensus()
	if err != nil {
		log.Panicln(err)
	}

	for {
		cmd, err := readALine()
		if err != nil {
			fmt.Println("ERROR: ", err)
			continue
		}
		switch cmd := cmd.(type) {
		case *extCmd:
			err = handleExtend(or, cmd, consensus)
		case *listCmd:
			err = handleList(consensus)
		case *killCmd:
			err = handleKill(or)
		case *beginCmd:
			err = handleBegin(or, cmd)
		case *listConsCmd:
			err = handleListCons(or)
		case *demoStreamCmd:
			err = handleDemoStream(or, cmd)
		case *startSocksCmd:
			err = handleStartSocks(or)
		default:
			err = errors.New("unrec'd cmd")
		}
		if err != nil {
			fmt.Println("Error: ", err)
			continue
		}
	}
	select {
	case <-anythingFinished:
		log.Panicln("Somehow a main.go goroutine we spawned managed to finish, which is not good")
	}
}

func handleStartSocks(or *ORCtx) error {
	go socksMain(or)
	return nil
}

func handleDemoStream(or *ORCtx, cmd *demoStreamCmd) error {
	endChan, err := runChain()
	if err != nil {
		fmt.Println("runchain failed")
		return err
	}
	go func() {
		_ = <-endChan
		fmt.Println("exiting")
		os.Exit(-1)
	}()
	//_, _, err = reqAStream(or, "joelanders.net:80")
	return err
}

func startSocksStream(or *ORCtx, addrPort string, socksCon io.ReadWriteCloser) error {
	pc, strId, err := reqAStream(or, addrPort)
	if err != nil {
		return err
	}
	pc.pendingStreams[strId] = &PendingStream{strId, socksCon}
	return nil
}

func reqAStream(or *ORCtx, addrPort string) (*ProxyCircuit, StreamID, error) {
	streamId := NewStreamID()
	conn, err := or.RandomConnection()
	if err != nil {
		return nil, streamId, err
	}
	pc, err := conn.randomProxyCircuit()
	if err != nil {
		return nil, streamId, err
	}
	data := []byte(addrPort)
	data = append(data, []byte{0, 1, 0, 0, 0}...)
	conn.sendProxyCell(pc, streamId, RELAY_BEGIN, data)
	return pc, streamId, nil
}

func handleBegin(or *ORCtx, cmd *beginCmd) error {
	conn, ok := or.authenticatedConnections[cmd.fp]
	if !ok {
		return errors.New("couldn't find that connection")
	}
	pc, ok := conn.proxyCircuits[cmd.circId]
	if !ok {
		return errors.New("couldn't find that proxy circuit")
	}
	data := []byte("joelanders.net:80")
	data = append(data, []byte{1, 0, 0, 0}...)
	return conn.sendProxyCell(pc, cmd.strId, RELAY_BEGIN, data)
}

func handleKill(or *ORCtx) error {
	or.DestroyAllProxyCircuits()
	fmt.Println("wait a tick, because I don't know when those'll make it through the queue...")
	return nil
}

func handleListCons(or *ORCtx) error {
	for fp, conn := range or.authenticatedConnections {
		for pc, _ := range conn.proxyCircuits {
			fmt.Printf("conn %s has pc %d\n", fp.String(), pc)
		}
	}
	return nil
}

func handleList(consensus *zoossh.Consensus) error {
	count := 0
	for f := range consensus.RouterStatuses {
		st, ok := consensus.Get(f)
		if !ok {
			fmt.Println("it was there, now it's gone...")
			continue
		}
		fmt.Println(st.Fingerprint)
		fmt.Println(st.Address)
		fmt.Println(st.Flags)
		if count > 8 {
			break
		}
		count++
	}
	return nil
}

func handleExtend(or *ORCtx, cmd *extCmd, consensus *zoossh.Consensus) error {
	fmt.Println("you want to extend circuit ", cmd.extCirc)
	circId := cmd.extCirc // this might get reassigned at the end of the for loop
	for _, fp := range cmd.fprints {
		conDesc, ok := consensus.Get(fp.String())
		if !ok {
			return errors.New("not found; bailing")
		}
		ntorOnionKey, err := getNtorOnionKey(conDesc.MicroDigest)
		if err != nil {
			return errors.New("couldn't get ntor key")
		}
		//fmt.Println(fp, conDesc.Address, conDesc.ORPort, conDesc.MicroDigest, ntorOnionKey)

		addressBytes := make([]byte, 6)
		copy(addressBytes[0:4], []byte(conDesc.Address.To4()))
		addressBytes[4] = byte(conDesc.ORPort >> 8)
		addressBytes[5] = byte(conDesc.ORPort & 0xff)
		ntorDec, err := base64.StdEncoding.DecodeString(ntorOnionKey)
		if err != nil {
			return errors.New("couldn't decode ntoronionkey")
		}
		var ntorBytes [32]byte
		copy(ntorBytes[:], ntorDec[0:32])
		doneChan, err := or.RequestProxyCircuit(circId, addressBytes, fp, ntorBytes)
		if err != nil {
			return errors.New("reqproxycirc failed")
		}
		fmt.Println("sending...")
		newCircId := <-doneChan
		if newCircId != circId {
			fmt.Println("...created circuit id", newCircId)
		} else {
			fmt.Println("...extended circuit id", circId)
		}
		circId = newCircId
	}
	return nil
}

type Cmd interface{}

type extCmd struct {
	extCirc CircuitID
	fprints []Fingerprint
}

type listCmd struct{}
type listConsCmd struct{}
type killCmd struct{}
type beginCmd struct {
	fp     Fingerprint
	circId CircuitID
	strId  StreamID
}
type demoStreamCmd struct {
	nOrs int
}
type startSocksCmd struct{}

func readALine() (Cmd, error) {
	line, err = reader.ReadString('\n')
	if err != nil {
		return nil, errors.New("readstring error")
	}
	line = strings.TrimSpace(line)
	cmdAndArgs := strings.SplitN(line, " ", 2)
	if len(cmdAndArgs) < 1 {
		return nil, errors.New("bad line--nothing here?")
	}
	switch cmdAndArgs[0] {
	case "extend":
		return parseExtend(line)
	case "listsome":
		return &listCmd{}, nil
	case "killall":
		return &killCmd{}, nil
	case "sendbegin":
		return parseBegin(line)
	case "listcons":
		return &listConsCmd{}, nil
	case "demostream":
		return parseDemoStream(line)
	case "startsocks":
		return &startSocksCmd{}, nil
	default:
		return nil, errors.New("unrecognized")
	}
}

func parseDemoStream(line string) (*demoStreamCmd, error) {
	entries := strings.SplitN(line, " ", 4)
	if len(entries) != 2 {
		return nil, errors.New("bad line")
	}
	nOrs, err := strconv.ParseUint(entries[1], 10, 0)
	if err != nil {
		return nil, errors.New("couldn't parse nOrs")
	}
	return &demoStreamCmd{int(nOrs)}, nil
}

func parseBegin(line string) (*beginCmd, error) {
	entries := strings.SplitN(line, " ", 4)
	if len(entries) != 4 {
		return nil, errors.New("bad line")
	}
	fpr, err := hex.DecodeString(entries[1])
	if err != nil {
		return nil, errors.New("couldn't parse fingerprint")
	}
	circId, err := strconv.ParseUint(entries[2], 10, 32)
	if err != nil {
		return nil, errors.New("couldn't parse circid")
	}
	strId, err := strconv.ParseUint(entries[3], 10, 16)
	if err != nil {
		return nil, errors.New("couldn't parse streamid")
	}
	var fp [20]byte
	copy(fp[:], fpr[:])
	return &beginCmd{Fingerprint(fp), CircuitID(circId), StreamID(strId)}, nil
}

func parseExtend(line string) (*extCmd, error) {
	entries := strings.SplitN(line, " ", 3)
	if len(entries) != 3 {
		return nil, errors.New("bad line")
	}
	circID, err := strconv.ParseUint(entries[1], 10, 32)
	if err != nil {
		return nil, errors.New("couldn't parse circid")
	}

	fprints := strings.Split(entries[2], ",")
	if len(fprints) < 1 {
		return nil, errors.New("no fprints")
	}
	fprints2 := make([]Fingerprint, len(fprints))
	for i, fprint := range fprints {
		fprints[i] = strings.TrimSpace(fprint)
		if len(fprints[i]) != 40 {
			return nil, errors.New("bad fprint")
		}
		bytes, err := hex.DecodeString(fprints[i])
		if err != nil {
			return nil, errors.New("bad hex?")
		}
		var bytAry [20]byte
		copy(bytAry[:], bytes[:])
		fprints2[i] = Fingerprint(bytAry)
	}

	return &extCmd{CircuitID(circID), fprints2}, nil
}

func getNtorOnionKey(microDigest string) (string, error) {
	// http because we've got the hash of the data from the (hopefully authd) consensus
	//resp, err := http.Get("http://longclaw.riseup.net/tor/micro/d/" + microDigest)
	resp, err := http.Get("http://86.59.21.38/tor/micro/d/" + microDigest)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(body)
	calcedDigest := base64.StdEncoding.EncodeToString(sum[:])

	if calcedDigest[:len(microDigest)] != microDigest {
		return "", errors.New("digest didn't match")
	}

	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		words := strings.Split(line, " ")
		if words[0] == "ntor-onion-key" {
			return words[1], nil
		}
	}
	return "", errors.New("didn't find key")
}

// fix this. oughta be a stdlib thing that sends reader -> file without me having to create a buffer
// but this is faster than looking for it.
func getConsensus() (*zoossh.Consensus, error) {
	t := time.Now().UTC()
	basename := fmt.Sprintf("%4d-%02d-%02d-%02d-00-00-consensus-microdesc", t.Year(), int(t.Month()), t.Day(), t.Hour()-1)
	filepath := datadir + basename
	fmt.Println("looking for consensus at", filepath)
	collectorPath := "https://collector.torproject.org/recent/relay-descriptors/microdescs/consensus-microdesc/" + basename
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		fmt.Println("downloading new consensus-microdesc from", collectorPath)
		resp, err := http.Get(collectorPath)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		if err := ioutil.WriteFile(filepath, body, 0600); err != nil {
			return nil, err
		}
	}
	consensus, err := zoossh.LazilyParseMicroConsensusFile(filepath)
	if err != nil {
		return nil, err
	}
	fmt.Println("read", consensus.Length(), "descriptors")
	return consensus, nil
}
