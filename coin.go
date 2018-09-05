package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const versionNumber = 70015

var genesisHash = [32]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xd6, 0x68, 0x9c, 0x08, 0x5a, 0xe1, 0x65, 0x83, 0x1e, 0x93, 0x4f, 0xf7, 0x63, 0xae, 0x46, 0xa2, 0xa6, 0xc1, 0x72, 0xb3, 0xf1, 0xb6, 0x0a, 0x8c, 0xe2, 0x6f}

var httpClient *http.Client

var elog *log.Logger

const CLR_0 = "\x1b[30;1m"
const CLR_R = "\x1b[31;1m"
const CLR_G = "\x1b[32;1m"
const CLR_Y = "\x1b[33;1m"
const CLR_B = "\x1b[34;1m"
const CLR_M = "\x1b[35;1m"
const CLR_C = "\x1b[36;1m"
const CLR_W = "\x1b[37;1m"
const CLR_N = "\x1b[0m"

type Peer struct {
	IP      string
	Version VersionPayload
}

var peers []Peer

type Header struct {
	StartString [4]byte  // Magic bytes indicating the originating network; used to seek to next message when stream state is unknown.
	CommandName [12]byte // ASCII string which identifies payload message type. Followed by nulls (0x00) to pad out byte count; for example: version\0\0\0\0\0
	PayloadSize uint32   // Number of bytes in payload.
	Checksum    [4]byte  // First 4 bytes of SHA256(SHA256(payload)). Default is 0x5df6e0e2 (SHA256(SHA256(<empty string>)))
}

func (h *Header) encode() []byte {
	b := &bytes.Buffer{}

	binary.Write(b, binary.LittleEndian, h.StartString)
	binary.Write(b, binary.LittleEndian, h.CommandName)
	binary.Write(b, binary.LittleEndian, h.PayloadSize)
	binary.Write(b, binary.LittleEndian, h.Checksum)

	return b.Bytes()
}

func decodeHeader(buf []byte) (Header, error) {
	var err error
	var h Header

	b := bytes.NewReader(buf)

	err = binary.Read(b, binary.LittleEndian, &h.StartString)
	if err != nil {
		return h, err
	}
	err = binary.Read(b, binary.LittleEndian, &h.CommandName)
	if err != nil {
		return h, err
	}
	err = binary.Read(b, binary.LittleEndian, &h.PayloadSize)
	if err != nil {
		return h, err
	}
	err = binary.Read(b, binary.LittleEndian, &h.Checksum)
	if err != nil {
		return h, err
	}
	return h, nil
}

type GetBlocksMessage struct {
	Version           int32
	BlockHeaderHashes [][32]byte
	StopHash          [32]byte
}

func encodeVarInt(i int64) []byte {
	b := &bytes.Buffer{}

	if i < 253 {
		binary.Write(b, binary.LittleEndian, uint8(i))
	} else if i <= 0xFFFF {
		b.WriteByte(0xFD)
		binary.Write(b, binary.LittleEndian, uint16(i))
	} else if i < 0xFFFFFFFF {
		b.WriteByte(0xFE)
		binary.Write(b, binary.LittleEndian, uint32(i))
	} else {
		b.WriteByte(0xFF)
		binary.Write(b, binary.LittleEndian, uint64(i))
	}

	return b.Bytes()
}

func decodeVarInt(b []byte) (uint64, []byte) {

	if b[0] < 253 {
		ret, i := binary.Uvarint(b[1:2])
		return ret, append(b[i+1:], b[:i+1]...)
	} else if b[0] == 0xFD {
		ret, i := binary.Uvarint(b[1:3])
		return ret, append(b[i+1:], b[:i+1]...)
	} else if b[0] == 0xFE {
		ret, i := binary.Uvarint(b[1:6])
		return ret, append(b[i+1:], b[:i+1]...)
	} else if b[0] == 0xFF {
		ret, i := binary.Uvarint(b[1:10])
		return ret, append(b[i+1:], b[:i+1]...)
	}
	return 0, b
}

func (g *GetBlocksMessage) encode() []byte {
	b := &bytes.Buffer{}

	err := binary.Write(b, binary.LittleEndian, g.Version)
	if err != nil {
		elog.Fatal(err)
	}
	//log.Printf("Composing GBM: %x", b.Bytes())
	err = binary.Write(b, binary.LittleEndian, encodeVarInt(int64(len(g.BlockHeaderHashes))))
	if err != nil {
		elog.Fatal(err)
	}
	//log.Printf("Composing GBM: %x", b.Bytes())

	for _, hash := range g.BlockHeaderHashes {

		for i := len(hash) - 1; i >= 0; i-- {
			b.WriteByte(hash[i])
		}

		//log.Printf("Composing GBM: %x", b.Bytes())
	}

	err = binary.Write(b, binary.LittleEndian, g.StopHash)
	if err != nil {
		elog.Fatal(err)
	}
	//log.Printf("Composing GBM: %x", b.Bytes())

	//log.Printf("Encoded GetBlocks: %x", b.Bytes())

	return b.Bytes()
}

type Inventory struct {
	DataType uint
	Hash     [32]byte
}

type InvMessage struct {
	Count     uint
	Inventory []Inventory
}

type RejectMessage struct {
	Message string
	CCode   byte
	Reason  string
	Data    string
}

func decodeRejectMessage(b []byte) RejectMessage {

	rej := RejectMessage{}

	var length uint64
	length, b = decodeVarInt(b)
	b = append(b[:1], b[1:]...)

	rej.Message = string(b[:length])
	b = append(b[:length], b[length:]...)

	rej.CCode = b[0]
	b = append(b[:1], b[1:]...)

	length, b = decodeVarInt(b)
	b = append(b[:1], b[1:]...)

	rej.Reason = string(b[:length])
	b = append(b[:length], b[length:]...)

	rej.Data = string(b[:])

	return rej
}

func decodeInvMessage(buf []byte) (InvMessage, error) {
	var err error
	var inv InvMessage

	var dataType uint32
	var hash [32]byte
	var count uint32

	b := bytes.NewReader(buf)

	err = binary.Read(b, binary.LittleEndian, &count)
	if err != nil {
		elog.Print(err)
		return inv, err
	}
	inv.Count = uint(count)

	for i := 0; i < int(inv.Count); i++ {
		var inventory Inventory
		err = binary.Read(b, binary.LittleEndian, &dataType)
		if err != nil {
			elog.Print(err)
			return inv, err
		}
		inventory.DataType = uint(dataType)

		if b.Len() < 32 {
			buf := make([]byte, b.Len())
			_, err = b.Read(buf)
			if err != nil {
				elog.Print(err)
				return inv, err
			}
			log.Printf("Too few bytes remain to decode hash: %x", buf)
			break
		}
		err = binary.Read(b, binary.LittleEndian, &hash)
		if err != nil {
			elog.Print(err)
			return inv, err
		}
		inventory.Hash = hash

		inv.Inventory = append(inv.Inventory, inventory)
	}

	return inv, nil
}

type VersionPayload struct {
	Version           int32
	Services          uint64
	Timestamp         int64
	AddrRecvIP        [16]byte // IPv6 address, or IPv4-mapped-IPv6 ::ffff:127.0.0.1
	AddrRecvPort      uint16   // big-endian byte order
	AddrRecvServices  uint64   // Should be identical to `services` field above
	AddrTransIP       [16]byte // IPv6 address, or IPv4-mapped-IPv6 ::ffff:127.0.0.1
	AddrTransPort     uint16   // big-endian byte order
	AddrTransServices uint64   // Should be identical to `services` field above
	Nonce             uint64
	UserAgentBytes    uint8
	UserAgent         string
	StartHeight       int32
	Relay             bool
}

func decodeVersionMessage(buf []byte) (VersionPayload, error) {
	var err error
	var v VersionPayload

	b := bytes.NewReader(buf)

	err = binary.Read(b, binary.LittleEndian, &v.Version)
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.LittleEndian, &v.Services)
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.LittleEndian, &v.Timestamp)
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.LittleEndian, &v.AddrRecvServices)
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.BigEndian, &v.AddrRecvIP)
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.BigEndian, &v.AddrRecvPort)
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.LittleEndian, &v.AddrTransServices)
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.BigEndian, &v.AddrTransIP)
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.BigEndian, &v.AddrTransPort)
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.LittleEndian, &v.Nonce)
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.LittleEndian, &v.UserAgentBytes)
	if err != nil {
		return v, err
	}

	//log.Printf("User agent byte count: %d", v.UserAgentBytes)

	uab := bytes.Buffer{}
	for i := 0; i < int(v.UserAgentBytes); i++ {
		c, err := b.ReadByte()
		if err != nil {
			elog.Print(err)
		}
		uab.WriteByte(c)
	}
	v.UserAgent = uab.String()

	err = binary.Read(b, binary.LittleEndian, &v.StartHeight)
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.LittleEndian, &v.Relay)
	if err != nil {
		return v, err
	}

	return v, err
}

func (v *VersionPayload) encode() []byte {
	b := &bytes.Buffer{}

	binary.Write(b, binary.LittleEndian, v.Version)
	binary.Write(b, binary.LittleEndian, v.Services)
	binary.Write(b, binary.LittleEndian, v.Timestamp)
	binary.Write(b, binary.LittleEndian, v.AddrRecvServices)
	binary.Write(b, binary.BigEndian, v.AddrRecvIP)
	binary.Write(b, binary.BigEndian, v.AddrRecvPort)
	binary.Write(b, binary.LittleEndian, v.AddrTransServices)
	binary.Write(b, binary.BigEndian, v.AddrTransIP)
	binary.Write(b, binary.BigEndian, v.AddrTransPort)
	binary.Write(b, binary.LittleEndian, v.Nonce)
	binary.Write(b, binary.LittleEndian, v.UserAgentBytes)
	_, _ = b.WriteString(v.UserAgent)
	binary.Write(b, binary.LittleEndian, v.StartHeight)
	binary.Write(b, binary.LittleEndian, v.Relay)

	return b.Bytes()
}

// Service Identifiers
// 0x00 Unnamed - This node is not a full node. It may not be able to provide any data except for the transactions it originates.
// 0x01 NODE_NETWORK - This is a full node and can be asked for full blocks.
// 			It should implement all protocol features available in its self-reported protocol version.

/*
The following annotated hexdump shows a version message.
(The message header has been omitted and the actual IP addresses have been replaced with RFC5737 reserved IP addresses.)

72110100 ........................... Protocol version: 70002
0100000000000000 ................... Services: NODE_NETWORK
bc8f5e5400000000 ................... Epoch time: 1415483324

0100000000000000 ................... Receiving node's services
00000000000000000000ffffc61b6409 ... Receiving node's IPv6 address
208d ............................... Receiving node's port number

0100000000000000 ................... Transmitting node's services
00000000000000000000ffffcb0071c0 ... Transmitting node's IPv6 address
208d ............................... Transmitting node's port number

128035cbc97953f8 ................... Nonce

0f ................................. Bytes in user agent string: 15
2f5361746f7368693a302e392e332f ..... User agent: /Satoshi:0.9.3/

cf050500 ........................... Start height: 329167
01 ................................. Relay flag: true
*/

func readBytes(conn net.Conn) []byte {
	conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	buf := make([]byte, 0, 20480) // big buffer
	tmp := make([]byte, 256)      // using small tmo buffer for demonstrating
	for {
		n, err := conn.Read(tmp)
		if err != nil {
			if err != io.EOF {
				elog.Println("read error:", err)
			}
			break
		}
		//fmt.Println("got", n, "bytes.")
		buf = append(buf, tmp[:n]...)
		conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	}
	//log.Println("total size:", len(buf))
	return buf
}

func handleCoinMessage(conn net.Conn) {

	buf := readBytes(conn)

	log.Printf("%sReceived request with bytes: %x %s%s", CLR_M, buf, string(buf), CLR_W)

	conn.Write([]byte("Message Received"))
	conn.Close()

}

func init() {
	elog = log.New(os.Stdout, "Error: ", log.LstdFlags|log.Lshortfile)
}

var knownBlocks []Inventory

func readKnownBlocks() {
	fp, err := filepath.Abs("knownBlocks.json")
	if err != nil {
		elog.Print(err)
	}

	jsonBytes, err := ioutil.ReadFile(fp)
	if err != nil {
		elog.Print(err)
	}

	err = json.Unmarshal(jsonBytes, &knownBlocks)
	if err != nil {
		elog.Print(err)
	}
}

func saveKnownBlocks() {

	fp, err := filepath.Abs("knownBlocks.json")
	if err != nil {
		elog.Print(err)
	}

	jsonBytes, err := json.Marshal(knownBlocks)
	if err != nil {
		elog.Print(err)
	}

	err = ioutil.WriteFile(fp, jsonBytes, 0755)
	if err != nil {
		elog.Print(err)
	}
}

func main() {

	var err error

	readKnownBlocks()

	go func() {

		ln, err := net.Listen("tcp", ":8333")
		if err != nil {
			elog.Print(err)
		}

		for {
			conn, err := ln.Accept()
			if err != nil {
				elog.Print(err)
			}

			handleCoinMessage(conn)
		}
	}()

	// Query bitcoin core DNS root for peers
	peers, err := discoverPeers()
	if err != nil {
		elog.Fatalf("DiscoverPeers returned error: %s", err.Error())
	}

	log.Printf("Got list of %d peers", len(peers))

	goodPeers := []Peer{}

	for _, peer := range peers {
		err := sendVersionMessage(peer.IP)
		if err != nil {
			//log.Printf("Failed to sendVersionMessage: %s", err.Error())
			elog.Printf("Failed to sendVersionMessage to peer %s", peer.IP)
			continue
		}

		goodPeers = append(goodPeers, peer)

		log.Printf("%sConnected to peer %s successfully%s", CLR_G, peer.IP, CLR_W)

		if len(goodPeers) > 1 {
			break
			//goto PEERSCONNECTED
		}
	}

	for _, goodPeer := range goodPeers {

		gbm := GetBlocksMessage{
			Version:           versionNumber,
			BlockHeaderHashes: [][32]byte{genesisHash},
			StopHash:          [32]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		}

		log.Printf("Sending GetBlocks to peer %v", goodPeer.IP)

		inv, err := sendGetBlocksMessage(gbm, goodPeer.IP)
		if err != nil {
			elog.Print(err)
			continue
		}

		log.Printf("%s +++++++ Received %d blocks%s", CLR_G, len(inv.Inventory), CLR_W)

		knownBlocks = append(knownBlocks, inv.Inventory...)

		saveKnownBlocks()

	}

	//PEERSCONNECTED:

	// Connect to a peer using `version` message using sendVersionMessage()

	// After response `version` message received from peer
	// Send `verack` using sendVersionAckMessage()

	// Once connection established, keepalive by sending a message before 30 minutes of inactivity
	// 90 minutes of inactivity is assumed to be a closed connection

	for {

		// Doing some work here
		log.Print("Waiting for work")

		time.Sleep(10 * time.Second)
	}

}

func ipv4mappedipv6(addr string) ([16]byte, error) {

	peerIP := net.ParseIP(addr)
	if peerIP == nil {
		return [16]byte{}, errors.New("Failed to parse IP of peer")
	}

	//log.Printf("IP pre mod mapped: %v", peerIP[9])

	//peerIP = peerIP.To16()

	//peerIP[10] = byte(0xff)
	//peerIP[11] = byte(0xff)

	//log.Printf("IP mapped: %v", peerIP[9])

	//log.Printf("IP mapped: %v", buf.Bytes())
	var b [16]byte
	copy(b[:], peerIP)
	return b, nil
}

func bytesToCommand(b []byte) string {

	buf := &bytes.Buffer{}

	for i := 0; i < len(b); i++ {
		if b[i] == 0x00 {
			break
		}
		buf.WriteByte(b[i])
	}

	return buf.String()
}

func commandToBytes(s string) [12]byte {

	command := [12]byte{}

	for i := 0; i < 12; i++ {
		if i < len(s) {
			command[i] = byte(s[i])
		} else {
			command[i] = byte(0x00)
		}
	}
	return command
}

func sendGetBlocksMessage(v GetBlocksMessage, peer string) (*InvMessage, error) {
	rand.Seed(int64(time.Now().Unix()))

	bodyBytes := v.encode()

	//log.Printf("Body: %v", bodyBytes)
	bodySum1 := sha256.Sum256(bodyBytes)
	bodySum2 := sha256.Sum256(bodySum1[:])

	//log.Printf("Body checksum: %x", bodySum2)

	var arr [4]byte
	copy(arr[:], bodySum2[:4])

	h := Header{
		StartString: [4]byte{0xf9, 0xbe, 0xb4, 0xd9},
		CommandName: commandToBytes("getblocks"),
		PayloadSize: uint32(len(bodyBytes)),
		Checksum:    arr,
	}

	headerBytes := h.encode()

	//log.Printf("Header: %x", headerBytes)

	reqBuf := bytes.NewBuffer(headerBytes)
	_, err := reqBuf.Write(bodyBytes)
	if err != nil {
		elog.Fatalf("Failed to write body to getblocks message. %s", err.Error())
	}
	if len(peer) > 15 {
		peer = fmt.Sprintf("%s%s%s", "[", peer, "]")
	}
	conn, err := net.DialTimeout("tcp", peer+":8333", time.Second*3)
	if err != nil {
		elog.Printf("Failed to send getblocks message. %s", err.Error())
		return nil, err
	}

	log.Printf("Writing %x to conn", reqBuf.Bytes())

	conn.SetWriteDeadline(time.Now().Add(time.Second * 15))
	_, err = conn.Write(reqBuf.Bytes())
	if err != nil {
		return nil, err
	}

	respBytes := readBytes(conn)
	if err != nil {
		return nil, err
	}

	log.Printf("Peer responded with: %#v", respBytes)

	//header, err := decodeHeader(respBytes)

	//log.Printf("Peer header: %#v", header)

	if len(respBytes) < 24 {
		return nil, errors.New(fmt.Sprintf("GetBlocks response too short: %#v", respBytes))
	}

	inventoryBlocks, err := decodeInvMessage(respBytes[24:])
	if err != nil {
		return nil, err
	}

	return &inventoryBlocks, nil

}

func sendVersionMessage(peer string) error {
	// version number
	// block
	// current time

	rand.Seed(int64(time.Now().Unix()))

	nonce := rand.Uint64()

	userAgent := "/Satoshi:0.16.0/"
	userAgentBytes := len(userAgent)

	peerMappedIP, err := ipv4mappedipv6(peer)
	if err != nil {
		elog.Print("Failed to return peerMappedIP: ", err)
	}

	localMappedIP, err := ipv4mappedipv6("63.226.144.254")
	if err != nil {
		elog.Print("Failed to return localMappedIP: ", err)
	}

	v := VersionPayload{
		Version:          versionNumber,
		Services:         0,
		Timestamp:        time.Now().Unix(),
		AddrRecvIP:       peerMappedIP,  // IPv6 address, or IPv4-mapped-IPv6 ::ffff:127.0.0.1
		AddrRecvPort:     8333,          // big-endian byte order
		AddrRecvServices: 0,             // Should be identical to `services` field above
		AddrTransIP:      localMappedIP, // IPv6 address, or IPv4-mapped-IPv6 ::ffff:127.0.0.1
		AddrTransPort:    8333,          // big-endian byte order
		Nonce:            nonce,
		UserAgentBytes:   uint8(userAgentBytes),
		UserAgent:        userAgent,
		StartHeight:      0,
		Relay:            false,
	}

	//log.Printf("VersionPayload: %#v", v)

	bodyBytes := v.encode()

	//log.Printf("Body: %v", bodyBytes)
	bodySum1 := sha256.Sum256(bodyBytes)
	bodySum2 := sha256.Sum256(bodySum1[:])

	var arr [4]byte
	copy(arr[:], bodySum2[:4])

	h := Header{
		StartString: [4]byte{0xf9, 0xbe, 0xb4, 0xd9},
		CommandName: commandToBytes("version"),
		PayloadSize: uint32(len(bodyBytes)),
		Checksum:    arr,
	}

	//log.Printf("Header: %#v", h)

	headerBytes := h.encode()

	reqBuf := bytes.NewBuffer(headerBytes)
	_, err = reqBuf.Write(bodyBytes)
	if err != nil {
		elog.Fatalf("Failed to write body to version message. %s", err.Error())
	}
	if len(peer) > 15 {
		peer = fmt.Sprintf("%s%s%s", "[", peer, "]")
	}
	conn, err := net.DialTimeout("tcp", peer+":8333", time.Second*3)
	if err != nil {
		elog.Printf("Failed to send version message. %s", err.Error())
		return err
	}

	//log.Printf("Writing %x to conn", reqBuf.Bytes())

	conn.SetWriteDeadline(time.Now().Add(time.Second * 5))
	_, err = conn.Write(reqBuf.Bytes())
	if err != nil {
		elog.Print(err)
	}

	respBytes := readBytes(conn)
	if err != nil {
		elog.Print(err)
	}

	//log.Printf("Peer responded with: %x", respBytes)

	//header, err := decodeHeader(respBytes)

	//log.Printf("Peer header: %#v", header)

	if len(respBytes) < 24 {
		return errors.New(fmt.Sprintf("Version response too small at %d bytes", len(respBytes)))
	}

	peerVersionMsg, err := decodeVersionMessage(respBytes[24:])
	if err != nil {
		elog.Print(err)
	}

	for _, p := range peers {
		if p.IP == peer {
			p.Version = peerVersionMsg
		}
	}

	//log.Printf("Peer version: %#v", peerVersion)

	conn.Close()

	// If version received in response, send verack with sendVersionAckMessage()
	if peerVersionMsg.Version != 0 {
		log.Printf("Peer %s %s returned version %v", peer, peerVersionMsg.UserAgent, peerVersionMsg.Version)

		err = sendVersionAckMessage(peer)
		if err != nil {
			return err
		}

		return nil
	} else {
		return errors.New("No version received from peer")
	}

}

/*
Example Verack
f9beb4d9 ................... Start string: Mainnet
76657261636b000000000000 ... Command name: verack + null padding
00000000 ................... Byte count: 0
5df6e0e2 ................... Checksum: SHA256(SHA256(<empty>))
*/

func sendVersionAckMessage(peer string) error {
	// Send empty message. Just headers.

	//log.Printf("Body: %v", bodyBytes)
	bodySum1 := sha256.Sum256([]byte{})
	bodySum2 := sha256.Sum256(bodySum1[:])

	var arr [4]byte
	copy(arr[:], bodySum2[:4])

	h := Header{
		StartString: [4]byte{0xf9, 0xbe, 0xb4, 0xd9},
		CommandName: commandToBytes("verack"),
		PayloadSize: 0,
		Checksum:    arr,
	}

	headerBytes := h.encode()

	log.Printf("Verack Header: %#v", headerBytes)

	reqBuf := bytes.NewBuffer(headerBytes)

	conn, err := net.DialTimeout("tcp", peer+":8333", time.Second*3)
	if err != nil {
		elog.Printf("Failed to send verack message. %s", err.Error())
		return err
	}

	conn.SetWriteDeadline(time.Now().Add(time.Second * 5))
	_, err = conn.Write(reqBuf.Bytes())
	if err != nil {
		elog.Print(err)
	}

	/*
		respBytes := readBytes(conn)
		if err != nil {
			return err
		}
	*/

	//log.Printf("Peer responded to verack with: %x", respBytes)
	conn.Close()

	return nil
}

func discoverPeers() ([]Peer, error) {
	var peers []Peer
	var err error

	var dnsSeeds = []string{"seed.bitcoin.sipa.be", "dnsseed.bluematt.me", "dnsseed.bitcoin.dashjr.org", "seed.bitcoinstats.com", "seed.bitcoin.jonasschnelli.ch", "seed.btc.petertodd.org"}

	for _, seed := range dnsSeeds {
		hosts, err := net.LookupIP(seed)
		if err != nil {
			return peers, err
		}

		for _, v := range hosts {
			peers = append(peers, Peer{IP: v.String()})
		}

		if len(peers) > 20 {
			break
		}

	}

	return peers, err
}
