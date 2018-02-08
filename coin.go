package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"time"
	"fmt"
)

var httpClient *http.Client

type Peer struct {
	IP string
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

type VersionPayload struct {
	Version           int32
	Services          uint64
	Timestamp         int64
	AddrRecvIP        []byte // IPv6 address, or IPv4-mapped-IPv6 ::ffff:127.0.0.1
	AddrRecvPort      uint16 // big-endian byte order
	AddrRecvServices  uint64 // Should be identical to `services` field above
	AddrTransIP       []byte // IPv6 address, or IPv4-mapped-IPv6 ::ffff:127.0.0.1
	AddrTransPort     uint16 // big-endian byte order
	AddrTransServices uint64 // Should be identical to `services` field above
	Nonce             uint64
	UserAgentBytes    uint8
	UserAgent         string
	StartHeight       int32
	Relay             bool
}

func decode(buf []byte) (VersionPayload, error) {
	var err error
	var v VersionPayload

	b := bytes.NewReader(buf)

	err = binary.Read(b, binary.LittleEndian, v.Version)
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.LittleEndian, v.Timestamp)
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.BigEndian, v.AddrRecvIP)
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.BigEndian, v.AddrRecvPort)
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.LittleEndian, v.AddrRecvServices)
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.LittleEndian, v.AddrTransServices)
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.BigEndian, v.AddrTransIP)
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.BigEndian, v.AddrTransPort)
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.LittleEndian, v.Nonce)
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.LittleEndian, v.UserAgentBytes)
	if err != nil {
		return v, err
	}
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.LittleEndian, v.UserAgent)
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.LittleEndian, v.StartHeight)
	if err != nil {
		return v, err
	}
	err = binary.Read(b, binary.LittleEndian, v.Relay)
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
	buf := make([]byte, 0, 4096) // big buffer
	tmp := make([]byte, 256)     // using small tmo buffer for demonstrating
	for {
		n, err := conn.Read(tmp)
		if err != nil {
			if err != io.EOF {
				log.Println("read error:", err)
			}
			break
		}
		//fmt.Println("got", n, "bytes.")
		buf = append(buf, tmp[:n]...)

	}
	log.Println("total size:", len(buf))
	return buf
}

func handleCoinMessage(conn net.Conn) {

	buf := readBytes(conn)

	log.Printf("Received request with bytes: %x (%s)", buf, string(buf))

	conn.Write([]byte("Message Received"))
	conn.Close()

}

func init() {

}

func main() {

	var err error

	go func() {

		ln, err := net.Listen("tcp", ":8333")
		if err != nil {
			log.Print(err)
		}

		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Print(err)
			}
			go handleCoinMessage(conn)
		}
	}()

	// Query bitcoin core DNS root for peers
	peers, err := discoverPeers()
	if err != nil {
		log.Fatalf("DiscoverPeers returned error: %s", err.Error())
	}

	log.Printf("Got list of %d peers", len(peers))

	goodPeers := []Peer{}

	for _, peer := range peers {
		err := sendVersionMessage(peer.IP)
		if err != nil {
			//log.Printf("Failed to sendVersionMessage: %s", err.Error())
			log.Printf("Failed to sendVersionMessage to peer %s", peer.IP)
			continue
		}

		goodPeers = append(goodPeers, peer)

		log.Printf("Connecte to peer %s successfully", peer.IP)

		if len(goodPeers) > 5 {
			break
			//goto PEERSCONNECTED
		}
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

func ipv4mappedipv6(addr string) ([]byte, error) {

	peerIP := net.ParseIP(addr)
	if peerIP == nil {
		return []byte{}, errors.New("Failed to parse IP of peer")
	}

	//log.Printf("IP pre mod mapped: %v", peerIP[9])

	//peerIP = peerIP.To16()

	//peerIP[10] = byte(0xff)
	//peerIP[11] = byte(0xff)

	//log.Printf("IP mapped: %v", peerIP[9])

	//log.Printf("IP mapped: %v", buf.Bytes())

	return []byte(peerIP), nil
}

func sendVersionMessage(peer string) error {
	// version number
	// block
	// current time

	rand.Seed(int64(time.Now().Unix()))

	nonce := rand.Uint64()

	userAgent := "/Satoshi:5.12/"
	userAgentBytes := len(userAgent)

	peerMappedIP, err := ipv4mappedipv6(peer)
	if err != nil {
		log.Print("Failed to return peerMappedIP: ", err)
	}

	localMappedIP, err := ipv4mappedipv6("52.21.183.128")
	if err != nil {
		log.Print("Failed to return localMappedIP: ", err)
	}

	v := VersionPayload{
		Version:          70015,
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
		CommandName: [12]byte{0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00},
		PayloadSize: uint32(len(bodyBytes)),
		Checksum:    arr,
	}

	//log.Printf("Header: %#v", h)

	headerBytes := h.encode()

	reqBuf := bytes.NewBuffer(headerBytes)
	_, err = reqBuf.Write(bodyBytes)
	if err != nil {
		log.Fatalf("Failed to write body to version message. %s", err.Error())
	}
	if len(peer) > 15 {
		peer = fmt.Sprintf("%s%s%s","[",peer,"]")
	}
	conn, err := net.DialTimeout("tcp", peer+":8333", time.Second*3)
	if err != nil {
		log.Printf("Failed to send version message. %s", err.Error())
		return err
	}

	log.Printf("Writing %x to conn", reqBuf.Bytes())

	conn.SetWriteDeadline(time.Now().Add(time.Second * 5))
	_, err = conn.Write(reqBuf.Bytes())
	if err != nil {
		log.Print(err)
	}

	
		respBytes := readBytes(conn)
		if err != nil {
			log.Print(err)
		}

		log.Printf("Peer responded with: %x", respBytes)
	conn.Close()	
	
	// If version received in response, send verack with sendVersionAckMessage()

	sendVersionAckMessage(peer)
	return nil
}

/*
Example Verack
f9beb4d9 ................... Start string: Mainnet
76657261636b000000000000 ... Command name: verack + null padding
00000000 ................... Byte count: 0
5df6e0e2 ................... Checksum: SHA256(SHA256(<empty>))
*/

func sendVersionAckMessage(peer string) {
	// Send empty message. Just headers.

	h := Header{
		StartString: [4]byte{0xf9, 0xbe, 0xb4, 0xd9},
		CommandName: [12]byte{0x76, 0x65, 0x72, 0x61, 0x63, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		PayloadSize: 0,
		Checksum:    [4]byte{0x5d, 0xf6, 0xe0, 0xe2},
	}

	bodyBytes := h.encode()

	_ = bodyBytes

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

	}

	return peers, err
}
