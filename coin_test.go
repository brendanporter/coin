package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestValidVersionPayload(t *testing.T) {

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

		0x72,0x11,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xbc,0x8f,0x5e,0x54,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xc6,0x1b,0x64,0x09,0x20,0x8d,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xcb,0x00,0x71,0xc0,0x20,0x8d,0x12,0x80,0x35,0xcb,0xc9,0x79,0x53,0xf8,0f2f5361746f7368693a302e392e332fcf05050001

	*/

	knownGood := []byte{0x72, 0x11, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbc, 0x8f, 0x5e, 0x54, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xc6, 0x1b, 0x64, 0x09, 0x20, 0x8d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xcb, 0x00, 0x71, 0xc0, 0x20, 0x8d, 0x12, 0x80, 0x35, 0xcb, 0xc9, 0x79, 0x53, 0xf8, 0x0f, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68, 0x69, 0x3a, 0x30, 0x2e, 0x39, 0x2e, 0x33, 0x2f, 0xcf, 0x05, 0x05, 0x00, 0x01}

	v := VersionPayload{
		Version:           70002,
		Services:          binary.LittleEndian.Uint64([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
		Timestamp:         int64(1415483324),
		AddrRecvServices:  binary.LittleEndian.Uint64([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
		AddrRecvIP:        []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xc6, 0x1b, 0x64, 0x09},
		AddrRecvPort:      binary.BigEndian.Uint16([]byte{0x20, 0x8d}),
		AddrTransServices: binary.LittleEndian.Uint64([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
		AddrTransIP:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xcb, 0x00, 0x71, 0xc0},
		AddrTransPort:     binary.BigEndian.Uint16([]byte{0x20, 0x8d}),
		Nonce:             binary.LittleEndian.Uint64([]byte{0x12, 0x80, 0x35, 0xcb, 0xc9, 0x79, 0x53, 0xf8}),
		UserAgentBytes:    uint8(15),
		UserAgent:         "/Satoshi:0.9.3/",
		StartHeight:       329167,
		Relay:             true,
	}

	versionBytes := v.encode()

	t.Logf("Encoded: %x", versionBytes)

	t.Logf("Good   : %x", knownGood)

	if !bytes.Equal(versionBytes, knownGood) {
		t.Log("Version payload format incorrect")
		t.Fail()
	}

}

/*
func TestPeerDiscovery(t *testing.T) {

	peers, err := discoverPeers()
	if err != nil {
		t.Fatal("DiscoverPeers returned error: %s", err.Error())
	}

	if len(peers) == 0 {
		t.Fatal("Got zero peers. Expecting more.")
	} else {
		t.Logf("Peer discovery returned %d peers. Peer 1 IP: %s", len(peers), peers[0].IP)
	}

}

func TestPeerConnection(t *testing.T) {

	peers, err := discoverPeers()
	if err != nil {
		t.Fatal("DiscoverPeers returned error: %s", err.Error())
	}

	for _, peer := range peers {
		err := sendVersionMessage(peer.IP)
		if err != nil {
			//t.Logf("Failed to sendVersionMessage: %s", err.Error())
			continue
		}

	}

}
*/
