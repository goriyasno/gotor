package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
)

// startSocksStream sends the RELAY_BEGIN cell
func HandleCon(locCon net.Conn, or *ORCtx) error {
	// application sends us a SOCKS4 request
	req, err := readConnectRequest(locCon)
	if err != nil {
		log.Println(err)
		return err
	}

	err = startSocksStream(or, req.AddrPort(), locCon)
	return err
}

// call this when we get the RELAY_CONNECTED cell
func FinishSocks(locCon io.ReadWriteCloser) error {
	// we send them back an "approved" response
	err = sendConnectResp(locCon)
	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}

type command int

const (
	CONNECT command = iota
	BIND    command = iota
)

type ConReq struct {
	cmd       command
	ip        net.IP
	port      uint16
	user      string
	localConn net.Conn
}

func (req *ConReq) DestAddr() string {
	return fmt.Sprintf("%s:%d", req.ip.String(), req.port)
}

func (req *ConReq) String() string {
	clientAddr := req.localConn.RemoteAddr()
	return fmt.Sprintf("%s -> %s", clientAddr, req.DestAddr())
}

func (req *ConReq) AddrPort() string {
	return fmt.Sprintf("%s:%d", req.ip, req.port)
}

func readConnectRequest(c net.Conn) (conReq *ConReq, err error) {
	// read first 9 bytes from the connection
	var b [9]byte
	n, err := c.Read(b[:])
	if n != 9 || err != nil {
		return nil, errors.New("not enough in req")
	}

	// only socks v4 for now
	if b[0] != '\x04' {
		return nil, errors.New("not socks 4")
	}

	req := new(ConReq)

	if b[1] != 1 && b[1] != 2 {
		return nil, errors.New("bad command")
	}

	req.cmd = command(b[1])
	req.port = binary.BigEndian.Uint16(b[2:4])
	req.ip = net.IPv4(b[4], b[5], b[6], b[7])
	req.localConn = c

	return req, nil
}

func sendConnectResp(c io.ReadWriteCloser) error {
	// hard-coding success for now
	resp := [8]byte{0, '\x5a', 0, 0, 0, 0, 0, 0}
	c.Write(resp[:])
	return nil
}

func socksMain(or *ORCtx) {
	// Listen on TCP port 2000 on loopback interface
	l, err := net.Listen("tcp", "127.0.0.1:2000")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println(err)
		}
		go func() {
			err = HandleCon(conn, or)
			if err != nil {
				log.Println(err)
			}
		}()
	}
}
