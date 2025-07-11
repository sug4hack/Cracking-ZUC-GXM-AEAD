// ZUC-GXM AEAD Example
// This example demonstrates the ZUC-GXM AEAD algorithm using a manual implementation of GHASH
// and ZUC cipher. It encrypts a plaintext with associated data and generates a tag.

package main

import (
	"bytes"
	"errors"
	"fmt"

	"gitee.com/emmansun/gmsm/zuc"
)

type ZUCGXM struct {
	key   []byte
	nonce []byte
	h     [16]byte
}

func xorBlock(a, b [16]byte) (out [16]byte) {
	for i := 0; i < 16; i++ {
		out[i] = a[i] ^ b[i]
	}
	return
}

func xorSlice(dst, a, b []byte) {
	for i := range a {
		dst[i] = a[i] ^ b[i]
	}
}

// ---------------- Manual GHASH Implementation ----------------

func gfMul(X, Y [16]byte) (Z [16]byte) {
	var V = Y
	var R [16]byte
	R[0] = 0xe1

	var XBits [128]bool
	for i := 0; i < 16; i++ {
		for bit := 7; bit >= 0; bit-- {
			XBits[i*8+(7-bit)] = (X[i]>>uint(bit))&1 == 1
		}
	}

	for i := 0; i < 128; i++ {
		if XBits[i] {
			for j := 0; j < 16; j++ {
				Z[j] ^= V[j]
			}
		}
		lsb := V[15] & 1
		for k := 15; k > 0; k-- {
			V[k] = (V[k] >> 1) | ((V[k-1] & 1) << 7)
		}
		V[0] >>= 1
		if lsb == 1 {
			for j := 0; j < 16; j++ {
				V[j] ^= R[j]
			}
		}
	}
	return
}

func computeGHASHWithLen(H [16]byte, A, C []byte) [16]byte {
	var X [16]byte
	var block [16]byte

	tmpA := A
	for len(tmpA) >= 16 {
		copy(block[:], tmpA[:16])
		for i := 0; i < 16; i++ {
			X[i] ^= block[i]
		}
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
		for i := 0; i < 16; i++ {
			X[i] ^= block[i]
		}
		X = gfMul(X, H)
	}

	tmpC := C
	for len(tmpC) >= 16 {
		copy(block[:], tmpC[:16])
		for i := 0; i < 16; i++ {
			X[i] ^= block[i]
		}
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
		for i := 0; i < 16; i++ {
			X[i] ^= block[i]
		}
		X = gfMul(X, H)
	}

	var lenBlock [16]byte
	aBits := uint64(len(A)) * 8
	cBits := uint64(len(C)) * 8
	for i := 0; i < 8; i++ {
		lenBlock[7-i] = byte(aBits >> (8 * i))
		lenBlock[15-i] = byte(cBits >> (8 * i))
	}
	for i := 0; i < 16; i++ {
		X[i] ^= lenBlock[i]
	}
	X = gfMul(X, H)

	return X
}

// ---------------- ZUC-GXM AEAD ----------------

func (z *ZUCGXM) Encrypt(plaintext, aad []byte) ([]byte, []byte, error) {
	zs, err := zuc.NewCipher(z.key, z.nonce)
	if err != nil {
		return nil, nil, err
	}
	keystream := make([]byte, len(plaintext)+16)
	zs.XORKeyStream(keystream, keystream)
	Z0 := keystream[:16]
	Z1 := keystream[16:]

	ciphertext := make([]byte, len(plaintext))
	xorSlice(ciphertext, plaintext, Z1)

	Y := computeGHASHWithLen(z.h, aad, ciphertext)
	tag := make([]byte, 16)
	xorSlice(tag, Z0, Y[:])

	return ciphertext, tag, nil
}

func (z *ZUCGXM) Decrypt(ciphertext, aad, tag []byte) ([]byte, error) {
	zs, err := zuc.NewCipher(z.key, z.nonce)
	if err != nil {
		return nil, err
	}
	keystream := make([]byte, len(ciphertext)+16)
	zs.XORKeyStream(keystream, keystream)
	Z0 := keystream[:16]
	Z1 := keystream[16:]

	plaintext := make([]byte, len(ciphertext))
	xorSlice(plaintext, ciphertext, Z1)

	Y := computeGHASHWithLen(z.h, aad, ciphertext)
	calcTag := make([]byte, 16)
	xorSlice(calcTag, Z0, Y[:])

	if !bytes.Equal(tag, calcTag) {
		return nil, errors.New("tag mismatch")
	}
	return plaintext, nil
}

func main() {
	ctx := &ZUCGXM{
		key:   []byte("ZUC-KEY-12345678"),
		nonce: []byte("NONCE-AAAAAAA-12"),
		h:     [16]byte{0x1d, 0x72, 0x4d, 0x49, 0x25, 0x1b, 0x6d, 0x24, 0x84, 0x76, 0xcc, 0x6d, 0xa4, 0x3f, 0xe9, 0xd2},
	}

	plaintext := []byte("this is the secret message")
	aad := []byte("associated data")

	ciphertext, tag, err := ctx.Encrypt(plaintext, aad)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Ciphertext: %x\n", ciphertext)
	fmt.Printf("Tag:        %x\n", tag)

	decrypted, err := ctx.Decrypt(ciphertext, aad, tag)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Decrypted:  %s\n", decrypted)
}
