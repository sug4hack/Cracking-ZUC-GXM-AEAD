package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

// xorBlock performs XOR between two 16-byte blocks
func xorBlock(a, b [16]byte) (c [16]byte) {
	for i := 0; i < 16; i++ {
		c[i] = a[i] ^ b[i]
	}
	return
}

// gfMul performs multiplication in GF(2^128) with the fixed polynomial
func gfMul(X, Y [16]byte) (Z [16]byte) {
	V := Y
	for i := 0; i < 128; i++ {
		bit := (X[i/8] >> uint(7-(i%8))) & 1
		if bit == 1 {
			Z = xorBlock(Z, V)
		}
		lsb := V[15] & 1
		for j := 15; j > 0; j-- {
			V[j] = (V[j] >> 1) | ((V[j-1] & 1) << 7)
		}
		V[0] >>= 1
		if lsb == 1 {
			V[0] ^= 0xe1
		}
	}
	return
}

// computeGHASHWithLen implements manual GHASH with len(A)||len(C)
func computeGHASHWithLen(H [16]byte, A, C []byte) [16]byte {
	var X [16]byte
	var block [16]byte

	// Process AAD
	tmpA := A
	for len(tmpA) >= 16 {
		copy(block[:], tmpA[:16])
		X = xorBlock(X, block)
		X = gfMul(X, H)
		tmpA = tmpA[16:]
	}
	if len(tmpA) > 0 {
		for i := 0; i < 16; i++ {
			if i < len(tmpA) {
				block[i] = tmpA[i]
			} else {
				block[i] = 0
			}
		}
		X = xorBlock(X, block)
		X = gfMul(X, H)
	}

	// Process ciphertext
	tmpC := C
	for len(tmpC) >= 16 {
		copy(block[:], tmpC[:16])
		X = xorBlock(X, block)
		X = gfMul(X, H)
		tmpC = tmpC[16:]
	}
	if len(tmpC) > 0 {
		for i := 0; i < 16; i++ {
			if i < len(tmpC) {
				block[i] = tmpC[i]
			} else {
				block[i] = 0
			}
		}
		X = xorBlock(X, block)
		X = gfMul(X, H)
	}

	// Length block: len(A)*8 || len(C)*8
	var lenBlock [16]byte
	aBits := uint64(len(A)) * 8
	cBits := uint64(len(C)) * 8
	for i := 0; i < 8; i++ {
		lenBlock[7-i] = byte(aBits >> (8 * i))
		lenBlock[15-i] = byte(cBits >> (8 * i))
	}
	X = xorBlock(X, lenBlock)
	X = gfMul(X, H)

	return X
}

// bytesToBlock converts a 16-byte slice to a [16]byte block
func bytesToBlock(b []byte) [16]byte {
	var block [16]byte
	copy(block[:], b)
	return block
}

func main() {
	// GHASH key
	H := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	// Additional authenticated data
	A := []byte("authenticated-data")

	// Ciphertext C1 (2 blocks)
	C1 := make([]byte, 32)
	copy(C1[:16], []byte("0000000000000001"))
	copy(C1[16:], []byte("0000000000000000"))

	// Δ1 = 0...01 (last byte)
	var delta1 [16]byte
	delta1[15] = 0x01

	// Δ2 = H * Δ1
	delta2 := gfMul(delta1, H)

	// Buat blok XOR
	b1 := xorBlock(bytesToBlock(C1[:16]), delta1)
	b2 := xorBlock(bytesToBlock(C1[16:]), delta2)

	// Ciphertext C2 = C1 ⊕ Δ
	C2 := make([]byte, 32)
	copy(C2[:16], b1[:])
	copy(C2[16:], b2[:])

	// Hitung GHASH
	tag1 := computeGHASHWithLen(H, A, C1)
	tag2 := computeGHASHWithLen(H, A, C2)

	fmt.Println("C1:        ", hex.EncodeToString(C1))
	fmt.Println("C2:        ", hex.EncodeToString(C2))
	fmt.Println("GHASH(C1): ", hex.EncodeToString(tag1[:]))
	fmt.Println("GHASH(C2): ", hex.EncodeToString(tag2[:]))
	fmt.Println("Kolisi?    ", bytes.Equal(tag1[:], tag2[:]))
}
