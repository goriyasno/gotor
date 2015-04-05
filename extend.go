// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"log"
)

func (c *OnionConnection) handleRelayExtend(circ *Circuit, cell *RelayCell) ActionableError {
	data := cell.Data()

	Log(LOG_CIRC, "Got extend!")

	if circ.nextHop != nil {
		return CloseCircuit(errors.New("We already have a next hop."), DESTROY_REASON_PROTOCOL)
	}

	if circ.extendState != nil {
		return CloseCircuit(errors.New("Refusing attempt to extend a circuit twice"), DESTROY_REASON_PROTOCOL)
	}

	if len(data) != 212 {
		return CloseCircuit(errors.New("malformed EXTEND cell"), DESTROY_REASON_PROTOCOL)
	}

	// Check that we're not connecting back to the source
	if c.theyAuthenticated {
		sameFP := true
		for i := 0; i < 20; i++ {
			if c.theirFingerprint[i] != data[192+i] {
				sameFP = false
				break
			}
		}
		if sameFP {
			return CloseCircuit(errors.New("not extending to the source"), DESTROY_REASON_PROTOCOL)
		}
	}

	circReq := &CircuitRequest{}
	circReq.connHint.AddAddress(data[0:6])
	circReq.connHint.AddFingerprint(data[192:212])

	circReq.handshakeData = make([]byte, 186)
	copy(circReq.handshakeData, data[6:192])

	circReq.handshakeType = uint16(HANDSHAKE_TAP)
	circReq.successQueue = c.circuitReadQueue
	circReq.newHandshake = false
	circReq.localID = circ.id
	circReq.handshakeState = &CircuitHandshakeState{}

	circ.extendState = circReq.handshakeState

	if err := c.parentOR.RequestCircuit(circReq); err != nil {
		return CloseCircuit(err, DESTROY_REASON_INTERNAL)
	}

	return nil
}

func (c *OnionConnection) handleRelayExtend2(circ *Circuit, cell *RelayCell) ActionableError {
	Log(LOG_CIRC, "got extend")

	data := cell.Data()
	nspec := int(data[0])
	if 1+(nspec*2)+4 > len(data) {
		return CloseCircuit(errors.New("malformed EXTEND cell"), DESTROY_REASON_PROTOCOL)
	}

	if circ.nextHop != nil {
		return CloseCircuit(errors.New("We already have a next hop."), DESTROY_REASON_PROTOCOL)
	}

	if circ.extendState != nil {
		return CloseCircuit(errors.New("Refusing attempt to extend a circuit twice"), DESTROY_REASON_PROTOCOL)
	}

	circReq := &CircuitRequest{}
	circReq.newHandshake = true

	readPos := 1
	for i := 0; i < nspec; i++ {
		lstype := data[readPos]
		lslen := int(data[readPos+1])
		readPos += 2
		if readPos+lslen > len(data)-4 {
			return CloseCircuit(errors.New("malformed EXTEND cell"), DESTROY_REASON_PROTOCOL)
		}

		lsdata := data[readPos : readPos+lslen]
		readPos += lslen

		if lstype == 0 || lstype == 1 {
			if err := circReq.connHint.AddAddress(lsdata); err != nil {
				return CloseCircuit(err, DESTROY_REASON_PROTOCOL)
			}

		} else if lstype == 2 {
			if err := circReq.connHint.AddFingerprint(lsdata); err != nil {
				return CloseCircuit(err, DESTROY_REASON_PROTOCOL)
			}

			// Check that we're not connecting back to the source
			if c.theyAuthenticated {
				sameFP := true
				for i := 0; i < 20; i++ {
					if c.theirFingerprint[i] != lsdata[i] {
						sameFP = false
						break
					}
				}
				if sameFP {
					return CloseCircuit(errors.New("not extending to the source"), DESTROY_REASON_PROTOCOL)
				}
			}

		} else {
			Log(LOG_INFO, "ignoring unknown link specifier type %d", lstype)
		}
	}

	htype := BigEndian.Uint16(data[readPos : readPos+2])
	hlen := int(BigEndian.Uint16(data[readPos+2 : readPos+4]))
	readPos += 4
	if len(data) < readPos+hlen {
		return CloseCircuit(errors.New("malformed EXTEND cell"), DESTROY_REASON_PROTOCOL)
	}

	if nspec < 2 {
		return CloseCircuit(errors.New("EXTEND cell is super small.."), DESTROY_REASON_PROTOCOL)
	}

	circReq.handshakeData = make([]byte, hlen) // XXX use a cellbuf
	copy(circReq.handshakeData, data[readPos:readPos+hlen])

	circReq.handshakeType = htype
	circReq.successQueue = c.circuitReadQueue
	circReq.localID = circ.id
	circReq.handshakeState = &CircuitHandshakeState{}

	circ.extendState = circReq.handshakeState

	if err := c.parentOR.RequestCircuit(circReq); err != nil {
		return CloseCircuit(err, DESTROY_REASON_INTERNAL)
	}

	return nil
}

func (c *OnionConnection) handleCreated(cell Cell, newHandshake bool) ActionableError {
	var ourCirc *ProxyCircuit
	var theirCirc *RelayCircuit

	circid := cell.CircID()

	ourCirc, ours := c.proxyCircuits[circid]
	theirCirc, theirs := c.relayCircuits[circid]

	if !ours && !theirs {
		return RefuseCircuit(errors.New(cell.Command().String()+": no such circuit?"), DESTROY_REASON_PROTOCOL)
	}

	if ours && theirs {
		return RefuseCircuit(errors.New(cell.Command().String()+": ours and theirs?"), DESTROY_REASON_PROTOCOL)
	}

	Log(LOG_CIRC, "got a created: %d", circid)

	data := cell.Data()
	hlen := 148
	pos := 0
	if newHandshake {
		hlen = int(BigEndian.Uint16(data[0:2]))
		pos = 2
	}
	if hlen+pos > len(data) {
		return CloseCircuit(errors.New(cell.Command().String()+" cell badly formed"), DESTROY_REASON_PROTOCOL)
	}

	hdata := make([]byte, hlen) // XXX use a cellbuf
	copy(hdata, data[pos:pos+hlen])

	if theirs {
		// Relay the good news
		theirCirc.previousHop <- &CircuitCreated{
			id:            theirCirc.theirID,
			handshakeData: hdata,
			newHandshake:  newHandshake,
		}
	}

	if ours {
		kdf, err := NtorClientComplete(ourCirc.extendState, hdata)
		if err != nil {
			log.Println("finishing the ntor handshake didn't work")
			log.Println(err)
			return nil
		}
		Log(LOG_CIRC, "finished the ntor handshake")

		donechan := ourCirc.extendState.whenDone
		ourCirc.extendState = nil

		//todo super hax
		tempCircuit := *NewCircuit(999, kdf[0:20], kdf[20:40], kdf[40:56], kdf[56:72])
		ourCirc.forwardChain = append(ourCirc.forwardChain, tempCircuit.forward)
		ourCirc.backwardChain = append(ourCirc.backwardChain, tempCircuit.backward)

		if donechan != nil {
			donechan <- circid
		}
	}

	return nil
}

func (data *CircuitCreated) Handle(c *OnionConnection, circ *Circuit) ActionableError {
	if circ.nextHop != nil {
		panic("We managed to create two circuits?")
	}
	if circ.extendState == nil {
		panic("we didn't expect to extend") // XXX this could maybe be triggered by a client?
	}

	extendState := circ.extendState
	circ.nextHop = extendState.nextHop
	circ.nextHopID = extendState.nextHopID
	circ.extendState = nil

	if data.newHandshake {
		cell := GetCellBuf(false)
		defer ReturnCellBuf(cell) // XXX such a waste
		BigEndian.PutUint16(cell[0:2], uint16(len(data.handshakeData)))
		copy(cell[2:], data.handshakeData)

		// circuit streamid direction command data
		return c.sendRelayCell(circ, 0, BackwardDirection, RELAY_EXTENDED2, cell[0:2+len(data.handshakeData)])
	} else {
		// circuit streamid direction command data
		return c.sendRelayCell(circ, 0, BackwardDirection, RELAY_EXTENDED, data.handshakeData)
	}
}

func (req *CircuitRequest) Handle(c *OnionConnection, notreallyanthingatall *Circuit) ActionableError {
	newID := c.NewCircID()

	req.handshakeState.lock.Lock()
	aborted := req.handshakeState.aborted
	if !aborted {
		req.handshakeState.nextHop = c.circuitReadQueue
		req.handshakeState.nextHopID = newID
	}
	req.handshakeState.lock.Unlock()

	if aborted {
		Log(LOG_INFO, "Aborting CREATE - origin is gone")
		return nil
	}

	var writeCell Cell
	// the payloads for CREATE and EXTEND are similar.
	// EXTEND's payload needs layers of encryption.
	if req.extendCircId == 0 {
		cmd := CMD_CREATE2
		if !req.newHandshake {
			cmd = CMD_CREATE
		}
		writeCell = NewCell(c.negotiatedVersion, newID, cmd, nil)
		data := writeCell.Data()
		if req.newHandshake {
			BigEndian.PutUint16(data[0:2], uint16(req.handshakeType))
			BigEndian.PutUint16(data[2:4], uint16(len(req.handshakeData)))
			copy(data[4:], req.handshakeData)
		} else {
			copy(data, req.handshakeData)
		}
	} else {
		pc, ok := c.proxyCircuits[req.extendCircId]
		if !ok {
			return CloseCircuit(errors.New("missing a circ"), DESTROY_REASON_INTERNAL)
		}
		if &(pc.forward) == nil {
			err := errors.New("circuit doesn't have a crypto state")
			return CloseCircuit(err, DESTROY_REASON_INTERNAL)
		}
		if pc.extendState != nil {
			return CloseCircuit(errors.New("already extending"), DESTROY_REASON_INTERNAL)
		}
		writeCell = NewCell(c.negotiatedVersion, req.extendCircId, CMD_RELAY_EARLY, nil)
		data := writeCell.Data()
		data[0] = byte(RELAY_EXTEND2)
		copy(data[1:5], []byte{0, 0, 0, 0}) // recognized, stream
		// 5:9 digest (initially zero)
		//check if newhandshake
		BigEndian.PutUint16(data[9:11], uint16(len(req.handshakeData)+35))
		data[11] = byte(2) //nspec
		data[12] = byte(0) //lstype
		data[13] = byte(6) //lslen
		addr := req.connHint.address[0]
		copy(data[14:20], addr[:])
		data[20] = byte(2)  //lstype identity
		data[21] = byte(20) //lslen identity
		copy(data[22:42], req.handshakeState.fingerprint[:])
		BigEndian.PutUint16(data[42:44], uint16(req.handshakeType))
		BigEndian.PutUint16(data[44:46], uint16(len(req.handshakeData)))
		copy(data[46:], req.handshakeData)
		pc.forwardChain[len(pc.forwardChain)-1].digest.Write(data)
		digest := pc.forwardChain[len(pc.forwardChain)-1].digest.Sum(nil)
		copy(data[5:9], digest[0:4])

		for i := len(pc.forwardChain) - 1; i >= 0; i-- {
			pc.forwardChain[i].cipher.Crypt(data, data)
		}

		pc.extendState = req.handshakeState

	}

	// if we're sending a CREATE, we need to make a new circuit on our end
	// otherwise, we're EXTENDing an existing circuit
	if req.weAreInitiator {
		if req.extendCircId == 0 {
			c.proxyCircuits[writeCell.CircID()] = &ProxyCircuit{
				Circuit: Circuit{
					id:             writeCell.CircID(),
					extendState:    req.handshakeState,
					backwardWindow: NewWindow(1000),
					forwardWindow:  1000,
				},
				pendingStreams: make(map[StreamID]*PendingStream),
			}
		}
	} else {
		// XXX if they send data before the created2, it'll nicely work
		c.relayCircuits[writeCell.CircID()] = &RelayCircuit{
			id:          writeCell.CircID(),
			theirID:     req.localID,
			previousHop: req.successQueue,
		}
	}

	c.writeQueue <- writeCell.Bytes()

	return nil
}
