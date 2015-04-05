// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"io"
)

func (s *Stream) ProxyRun(circID CircuitID, circWindow *Window, queue CircReadQueue, conn io.ReadWriteCloser) {
	defer func() {
		conn.Close()

		s.backwardWindow.Abort()
		s.forwardWindow.Abort()
		circWindow.Abort()

		Log(LOG_CIRC, "Disconnected stream %d")
	}()

	readQueue := make(chan []byte, 5)

	// pulls things off conn and sticks them on readqueue
	go s.reader(conn, circWindow, readQueue)

	for {
		select {
		// this stuff comes from the onion circuit
		case data, ok := <-s.writeChan:
			if !ok {
				return
			}
			_, err := conn.Write(data)
			if err != nil {
				return
			}
			ReturnCellBuf(data)

			// this stuff comes from the tcp connection
			// we send it to the onion connection
		case data, ok := <-readQueue:
			if !ok {
				return
			}
			queue <- &StreamData{
				circuitID: circID,
				streamID:  s.id,
				data:      data,
			} // XXX this could deadlock
		}
	}
}
