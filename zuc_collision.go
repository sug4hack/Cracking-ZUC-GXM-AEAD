package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"gitee.com/emmansun/gmsm/zuc"
)

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
	// 2 ZUC keys dan 2 nonce yang berbeda
	K1 := []byte("ZUC-KEY-12345678") // 16 bytes
	K2 := []byte("ZUC-KEY-87654321")
	N1 := []byte("NONCE-A-12345678") // 16 bytes
	N2 := []byte("NONCE-B-87654321")

	// Panjang plaintext 32 byte (2 blok)
	length := 32

	// Generate Z1^{(1)} dari K1, N1
	zs1, err := zuc.NewCipher(K1, N1)
	if err != nil {
		panic(err)
	}
	Z1a := make([]byte, length)
	zs1.XORKeyStream(Z1a, make([]byte, length))

	// Generate Z1^{(2)} dari K2, N2
	zs2, err := zuc.NewCipher(K2, N2)
	if err != nil {
		panic(err)
	}
	Z1b := make([]byte, length)
	zs2.XORKeyStream(Z1b, make([]byte, length))

	// Buat P1 random
	P1 := make([]byte, length)
	_, _ = rand.Read(P1)

	// Buat P2 = P1 ⊕ Z1a ⊕ Z1b
	P2 := xorSlice(P1, xorSlice(Z1a, Z1b))

	// Enkripsi
	C1 := xorSlice(P1, Z1a)
	C2 := xorSlice(P2, Z1b)

	// Verifikasi
	fmt.Println("P1:", hex.EncodeToString(P1))
	fmt.Println("P2:", hex.EncodeToString(P2))
	fmt.Println("P1 == P2?", bytes.Equal(P1, P2))
	fmt.Println()

	fmt.Println("C1:", hex.EncodeToString(C1))
	fmt.Println("C2:", hex.EncodeToString(C2))
	fmt.Println("C1 == C2?", bytes.Equal(C1, C2))
}
