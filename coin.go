package main

import (
	//"fmt"
	"bytes"
	"encoding/binary"
	"net"
	//"net/http"
)

type Header struct {
	StartString [4]byte  // Magic bytes indicating the originating network; used to seek to next message when stream state is unknown.
	CommandName [12]byte // ASCII string which identifies payload message type. Followed by nulls (0x00) to pad out byte count; for example: version\0\0\0\0\0
	PayloadSize [4]byte  // Number of bytes in payload.
	Checksum    [4]byte  // First 4 bytes of SHA256(SHA256(payload)). Default is 0x5df6e0e2 (SHA256(SHA256(<empty string>)))
}

/*
// verack example header
f9beb4d9 ................... Start string: Mainnet
76657261636b000000000000 ... Command name: verack + null padding
00000000 ................... Byte count: 0
5df6e0e2 ................... Checksum: SHA256(SHA256(<empty>))
*/

type Peer struct {
	IP string
}

var peers []Peer

type Version struct {
	Version          int32
	Services         uint64
	Timestamp        int64
	AddrRecvIP       uint64 // IPv6 address, or IPv4-mapped-IPv6 :ffff:127.0.0.1
	AddrRecvPort     uint16 // big-endian byte order
	AddrRecvServices uint64 // Should be identical to `services` field above
	AddrTransIP      uint64 // IPv6 address, or IPv4-mapped-IPv6 :ffff:127.0.0.1
	AddrTransPort    uint16 // big-endian byte order
	Nonce            uint64
	UserAgentBytes   []byte
	UserAgent        string
	StartHeight      int32
	Relay            bool
}

func (v *Vesion) encode() []byte {
	b := &bytes.Buffer{}

	binary.Write(b, binary.LittleEndian, v.Version)
	binary.Write(b, binary.LittleEndian, v.Services)
	binary.Write(b, binary.LittleEndian, v.Timestamp)
	binary.Write(b, binary.LittleEndian, v.AddrRecvIP)
	binary.Write(b, binary.BigEndian, v.AddrRecvPort)
	binary.Write(b, binary.LittleEndian, v.AddrRecvServices)
	binary.Write(b, binary.LittleEndian, v.AddrTransIP)
	binary.Write(b, binary.BigEndian, v.AddrTransPort)
	binary.Write(b, binary.LittleEndian, v.Nonce)
	binary.Write(b, binary.LittleEndian, v.UserAgentBytes)
	binary.Write(b, binary.LittleEndian, v.UserAgent)
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

type Verack struct { // Version Acknowledgement

}

func main() {

	var err error
	// Query bitcoin core DNS root for peers
	peers, err = discoverPeers()
	if err != nil {
		fmt.Print("Failed to find peers: ", err)
	}

	// Connect to a peer using `version` message using sendVersionMessage()

	// After response `version` message received from peer
	// Send `verack` using sendVersionAckMessage()

	// Once connection established, keepalive by sending a message before 30 minutes of inactivity
	// 90 minutes of inactivity is assumed to be a closed connection

}

func sendVersionMessage(peer string) {
	// version number
	// block
	// current time

	// If version received in response, send verack with sendVersionAckMessage()
}

func sendVersionAckMessage(peer string) {

}

func discoverPeers() ([]Peer, error) {
	var peers []Peer

	host := "seed.bitcoin.sipa.be"
	hosts, err := net.LookupIP(host)
	if err != nil {
		return peers, err
	}

	for _, v := range hosts {
		peers = append(peers, Peer{IP: v.String()})
	}

	return peers, err
}
