// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"golang.org/x/crypto/curve25519"
)

func NtorClientPayload(servID [20]byte, onionPub [32]byte, clientPub [32]byte) ([84]byte, error) {
	var buffer [84]byte
	copy(buffer[0:20], servID[:])
	onionPubId := sha256.Sum256(onionPub[:]) //dunno if this is right
	copy(buffer[20:52], onionPubId[:])
	copy(buffer[52:84], clientPub[:])

	return buffer, nil
}

func NtorClientComplete(handshakeState *CircuitHandshakeState, servReply []byte) ([]byte, error) {
	var Yx [32]byte
	var x [32]byte
	var Y [32]byte
	copy(x[:], handshakeState.keys[0][:])
	copy(Y[:], servReply[:32])
	curve25519.ScalarMult(&Yx, &x, &Y)

	var Bx [32]byte
	var B [32]byte
	copy(B[:], handshakeState.onionPublic[:])
	curve25519.ScalarMult(&Bx, &x, &B)
	// XXX check for infinity

	var buffer bytes.Buffer
	mExpand := []byte("ntor-curve25519-sha256-1:key_expand")
	tKey := []byte("ntor-curve25519-sha256-1:key_extract")
	tMac := []byte("ntor-curve25519-sha256-1:mac")
	tVerify := []byte("ntor-curve25519-sha256-1:verify")

	buffer.Write(Yx[:])
	buffer.Write(Bx[:])
	buffer.Write(handshakeState.fingerprint[:])
	buffer.Write(handshakeState.onionPublic[:])
	buffer.Write(handshakeState.keys[1][:])
	buffer.Write(servReply[:32])
	buffer.Write([]byte("ntor-curve25519-sha256-1"))

	secretInput := buffer.Bytes()
	kdf := KDFHKDF(72, secretInput, tKey, mExpand)

	hhmac := hmac.New(sha256.New, tVerify)
	hhmac.Write(secretInput)
	verify := hhmac.Sum(nil)

	buffer.Reset()
	buffer.Write(verify)
	buffer.Write(handshakeState.fingerprint[:])
	buffer.Write(handshakeState.onionPublic[:])
	buffer.Write(servReply[:32])
	buffer.Write(handshakeState.keys[1][:])
	buffer.Write([]byte("ntor-curve25519-sha256-1Server"))
	authInput := buffer.Bytes()

	hhmac = hmac.New(sha256.New, tMac)
	hhmac.Write(authInput)
	auth := hhmac.Sum(nil)

	for i, v := range servReply[32:64] {
		if auth[i] != v {
			return nil, errors.New("auth didn't match server response")
		}
	}
	return kdf, nil
}
