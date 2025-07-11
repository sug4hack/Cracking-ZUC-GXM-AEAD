package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"gitee.com/emmansun/gmsm/zuc"
)

func xorBlock(a, b [16]byte) (c [16]byte) {
	for i := 0; i < 16; i++ {
		c[i] = a[i] ^ b[i]
	}
	return
}

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
	return Z
}

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

	// Process Ciphertext
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

	// Final length block: len(A)||len(C) in bits
	var lenBlock [16]byte
	binary.BigEndian.PutUint64(lenBlock[0:], uint64(len(A))*8)
	binary.BigEndian.PutUint64(lenBlock[8:], uint64(len(C))*8)
	X = xorBlock(X, lenBlock)
	X = gfMul(X, H)

	return X
}

func bytesToBlock(b []byte) [16]byte {
	var block [16]byte
	copy(block[:], b)
	return block
}

func xorSlice(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("xorSlice: length mismatch")
	}
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func main() {
	K := []byte("1234567890abcdef") // 16-byte ZUC key
	H := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	nonce := []byte("example-16-bytes") // 16-byte nonce
	A := []byte("exampleAAD-data")      // fixed AAD

	// Ciphertext C1 = X1 || X2
	X1 := []byte("0000000000000001")
	X2 := []byte("0000000000000000")
	C1 := append(X1, X2...)

	// Δ1 = 1, Δ2 = H ⋅ Δ1
	var delta1 [16]byte
	delta1[15] = 0x01
	delta2 := gfMul(delta1, H)

	// C2 = (X1 ⊕ Δ1) || (X2 ⊕ Δ2)
	b1 := xorBlock(bytesToBlock(X1), delta1)
	b2 := xorBlock(bytesToBlock(X2), delta2)
	C2 := append(b1[:], b2[:]...)

	// Generate keystream Z = Z0 || Z1
	total := len(C1) + 16
	zs, err := zuc.NewCipher(K, nonce)
	if err != nil {
		panic(err)
	}
	stream := make([]byte, total)
	zs.XORKeyStream(stream, make([]byte, total))
	Z0 := stream[:16]
	Z1 := stream[16:]

	// Plaintext P1 = C1 ⊕ Z1, P2 = C2 ⊕ Z1
	P1 := xorSlice(C1, Z1)
	P2 := xorSlice(C2, Z1)

	// Manual GHASH
	Y1 := computeGHASHWithLen(H, A, C1)
	Y2 := computeGHASHWithLen(H, A, C2)

	// Tag = Z0 ⊕ GHASH
	T1 := xorSlice(Z0, Y1[:])
	T2 := xorSlice(Z0, Y2[:])

	fmt.Println("P1:", hex.EncodeToString(P1))
	fmt.Println("P2:", hex.EncodeToString(P2))
	fmt.Println("P1 == P2?", bytes.Equal(P1, P2))

	fmt.Println("C1:", hex.EncodeToString(C1))
	fmt.Println("C2:", hex.EncodeToString(C2))

	fmt.Println("Tag1:", hex.EncodeToString(T1))
	fmt.Println("Tag2:", hex.EncodeToString(T2))
	fmt.Println("Tag1 == Tag2?", bytes.Equal(T1, T2))
}
