package main

import (
	"testing"
)

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
