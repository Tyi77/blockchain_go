package main

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewMerkleNode(t *testing.T) {
	data := [][]byte{
		[]byte("node1"),
		[]byte("node2"),
		[]byte("node3"),
	}

	// Level 1

	n1 := NewMerkleNode(nil, nil, data[0])
	n2 := NewMerkleNode(nil, nil, data[1])
	n3 := NewMerkleNode(nil, nil, data[2])
	n4 := NewMerkleNode(nil, nil, data[2])

	// Level 2
	n5 := NewMerkleNode(n1, n2, nil)
	n6 := NewMerkleNode(n3, n4, nil)

	// Level 3
	n7 := NewMerkleNode(n5, n6, nil)

	assert.Equal(
		t,
		"9635e667789f2486e21030fe9a2d93f7f0d30bde04df172a4115c5edd420ea6d777e1c2f1ca30fd3f00dacd6bb7f6bcb",
		hex.EncodeToString(n5.Data),
		"Level 1 hash 1 is correct",
	)
	assert.Equal(
		t,
		"caf01e770dc54d8b8dcc1804778ae07dcdc34c2d50d91dfe2e5069125a481f214bdafda466ae9f38a144deb4915f14b3",
		hex.EncodeToString(n6.Data),
		"Level 1 hash 2 is correct",
	)
	assert.Equal(
		t,
		"29aaed26362d551bbd2b42dd0b7f41d1b823f32fb90c617f10df720d0184538e1222ca1666391b75d48b7cace146ab31",
		hex.EncodeToString(n7.Data),
		"Root hash is correct",
	)
}

func TestNewMerkleTree(t *testing.T) {
	data := [][]byte{
		[]byte("node1"),
		[]byte("node2"),
		[]byte("node3"),
	}
	// Level 1
	n1 := NewMerkleNode(nil, nil, data[0])
	n2 := NewMerkleNode(nil, nil, data[1])
	n3 := NewMerkleNode(nil, nil, data[2])
	n4 := NewMerkleNode(nil, nil, data[2])

	// Level 2
	n5 := NewMerkleNode(n1, n2, nil)
	n6 := NewMerkleNode(n3, n4, nil)

	// Level 3
	n7 := NewMerkleNode(n5, n6, nil)

	rootHash := fmt.Sprintf("%x", n7.Data)
	mTree := NewMerkleTree(data)

	assert.Equal(t, rootHash, fmt.Sprintf("%x", mTree.RootNode.Data), "Merkle tree root hash is correct")
}
