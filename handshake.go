package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"net"
	"os"
)

type Packet struct {
	capability uint32
	sequence   uint8
	user       string
	password   string
	database   string
	salt       []byte
	charset    byte
}

var pkg Packet

const (
	CLIENT_LONG_PASSWORD uint32 = 1 << iota
	CLIENT_FOUND_ROWS
	CLIENT_LONG_FLAG
	CLIENT_CONNECT_WITH_DB
	CLIENT_NO_SCHEMA
	CLIENT_COMPRESS
	CLIENT_ODBC
	CLIENT_LOCAL_FILES
	CLIENT_IGNORE_SPACE
	CLIENT_PROTOCOL_41
	CLIENT_INTERACTIVE
	CLIENT_SSL
	CLIENT_IGNORE_SIGPIPE
	CLIENT_TRANSACTIONS
	CLIENT_RESERVED
	CLIENT_SECURE_CONNECTION
	CLIENT_MULTI_STATEMENTS
	CLIENT_MULTI_RESULTS
	CLIENT_PS_MULTI_RESULTS
	CLIENT_PLUGIN_AUTH
	CLIENT_CONNECT_ATTRS
	CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
)

func main() {
	if len(os.Args) != 5 && len(os.Args) != 4 {
		fmt.Printf("handshake ip:port user passwd database\n")
		return
	}
	conn, err := net.Dial("tcp", os.Args[1])
	pkg.user = os.Args[2]
	pkg.password = os.Args[3]
	if len(os.Args) == 5 {
		pkg.database = os.Args[4]
	}
	if err == nil {
		if buf, err := readPacket(conn); err == nil {
			if err := parseInitialHandshake(buf); err == nil {
				data, _ := authWriteHandshake()
				conn.Write(data)
				if err := readHandshakeOK(conn); err == nil {
					fmt.Printf("handshake ok\n")
				} else {
					fmt.Printf("handshake failed\n")
				}
			}
		}
	} else {
		fmt.Printf("connect failed\n")
	}
}

func parseInitialHandshake(buf []byte) error {
	// fmt.Printf("parseInitialHandshake:")
	// for x := range buf {
	// fmt.Printf("%x ", buf[x])
	// }
	// fmt.Printf("\n")
	proctocol := buf[0]
	pos := bytes.IndexByte(buf[1:], 0x00) + 1
	server_version := string(buf[1:pos])
	pos++
	conncetion_id := buf[pos : pos+4]
	pos += 4
	auth_plugin_data1 := buf[pos : pos+8]
	pos += 8
	filler := buf[pos]
	pos++
	capability_flag1 := buf[pos : pos+2]
	pos += 2
	charset := buf[pos]
	pos++
	status_flag := binary.LittleEndian.Uint16(buf[pos : pos+2])
	pos += 2
	capability_flag2 := buf[pos : pos+2]
	pos += 2
	auth_plugin_len := int8(buf[pos])
	pos++
	auth_remain_len := int(auth_plugin_len - 8)
	pos += 10
	auth_plugin_data2 := buf[pos : pos+12]
	pos += 12 + 1
	// fmt.Printf("auth_remain_len:%d\n", auth_remain_len)
	auth_plugin_name := string(buf[pos:len(buf)])
	auth_plugin_data := make([]byte, 20)
	copy(auth_plugin_data[0:8], auth_plugin_data1)
	copy(auth_plugin_data[8:], auth_plugin_data2)
	pkg.salt = auth_plugin_data
	capability_flag := uint32(binary.LittleEndian.Uint16(capability_flag2)<<16) | uint32(binary.LittleEndian.Uint16(capability_flag1))
	pkg.capability = capability_flag
	fmt.Printf("protocol:%x\n", proctocol)
	fmt.Printf("server_version:%X, str:%s\n", []byte(server_version), server_version)
	fmt.Printf("conncetion_id:%X, NUM:%d\n", conncetion_id, binary.LittleEndian.Uint32(conncetion_id))
	fmt.Printf("auth_plugin_data1:%X\n", auth_plugin_data1)
	fmt.Printf("filler:%x\n", filler)
	fmt.Printf("capability_flag1:%X\n", capability_flag1)
	fmt.Printf("charset:%x\n", charset)
	fmt.Printf("status_flag:%X\n", status_flag)
	fmt.Printf("capability_flag2:%X\n", capability_flag2)
	fmt.Printf("auth_plugin_len:%X, len:%d\n", byte(auth_plugin_len), auth_remain_len)
	fmt.Printf("auth_plugin_data2:%X\n", auth_plugin_data2)
	fmt.Printf("auth_plugin_name:%X, str:%s\n", []byte(auth_plugin_name), auth_plugin_name)

	return nil
}
func authWriteHandshake() ([]byte, error) {
	capability := CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_LONG_PASSWORD | CLIENT_TRANSACTIONS | CLIENT_LONG_FLAG
	capability &= pkg.capability
	// capability
	//max-packet size
	//charset
	//reserved
	length := 4 + 4 + 1 + 23
	length += len(pkg.user) + 1
	auth := CalPassword(pkg.salt, []byte(pkg.password))
	length += 1 + len(auth)
	if len(pkg.database) > 0 {
		capability |= CLIENT_CONNECT_WITH_DB
		length += len(pkg.database) + 1
	}
	data := make([]byte, length+4)
	data[0] = byte(length)
	data[1] = byte(length >> 8)
	data[2] = byte(length >> 16)
	data[3] = pkg.sequence + 1
	data[4] = byte(capability)
	data[5] = byte(capability >> 8)
	data[6] = byte(capability >> 16)
	data[7] = byte(capability >> 24)
	// maxlen := uint32(1024)
	// data[8] = byte(maxlen)
	// data[9] = byte(maxlen >> 8)
	// data[10] = byte(maxlen >> 16)
	// data[11] = byte(maxlen >> 24)
	data[12] = pkg.charset
	pos := 13 + 23
	if len(pkg.user) > 0 {
		pos += copy(data[pos:], pkg.user)
	}
	pos++ //NULL
	data[pos] = byte(len(auth))
	pos += 1 + copy(data[pos+1:], auth)
	//pos++ //NULL
	if len(pkg.database) > 0 {
		pos += copy(data[pos:], pkg.database)
	}
	//data[pos] = 0x00
	// for i := range auth {
	// fmt.Printf("%x ", auth[i])
	// }
	// fmt.Printf("\n")
	// fmt.Printf("datalen:%d\n", len(auth))
	// for i := range data {
	// fmt.Printf("%x ", data[i])
	// }
	// fmt.Printf("\n")
	//fmt.Printf("data:len:%d, %X\n", len(data), data)
	return data, nil
}
func readHandshakeOK(conn net.Conn) error {
	if buf, err := readPacket(conn); err != nil {
		return err
	} else {
		if buf[0] == 0x00 {
			return nil
		} else {
			pos := 1
			code := binary.LittleEndian.Uint16(buf[pos:])
			pos += 2 + 1
			state := string(buf[pos : pos+5])
			pos += 5
			fmt.Errorf("handshake code:%d,state:%s, error%s\n", code, state, string(buf[pos:]))
		}
	}
	return nil
}
func readPacket(conn net.Conn) ([]byte, error) {
	head := []byte{0, 0, 0, 0}
	length := 0
	//sequence := 0
	if readlen, err := conn.Read(head); err == nil && readlen == 4 {
		length = int(uint32(head[0]) | uint32(head[1])<<8 | uint32(head[2])<<16)
		pkg.sequence = uint8(head[3])
		// fmt.Printf("sequence:%d\n", pkg.sequence)
	} else {
		return nil, fmt.Errorf("read head error")
	}
	if length < 1 {
		return nil, fmt.Errorf("read data error")
	}
	buf := make([]byte, length)

	if readlen, err := conn.Read(buf); err == nil && readlen == length {
		// for i := range buf {
		// fmt.Printf("%x ", buf[i])
		// }
		// fmt.Printf("\n")
		return buf, nil
	} else {
		return nil, fmt.Errorf("read data error")
	}
}
func CalPassword(salt, pwd []byte) []byte {
	// fmt.Printf("len:%d, %X,  pwd:%s\n", len(salt), salt, string(pwd))
	crypt := sha1.New()
	crypt.Write(pwd)
	stage1 := crypt.Sum(nil)
	crypt.Reset()
	crypt.Write(stage1)
	hash := crypt.Sum(nil)
	crypt.Reset()
	crypt.Write(salt)
	crypt.Write(hash)
	salt = crypt.Sum(nil)
	for i := range salt {
		salt[i] ^= stage1[i]
	}
	return salt
}
