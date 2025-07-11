package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"gitee.com/emmansun/gmsm/zuc"
)

func xor(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func gfMul(X, Y [16]byte) (Z [16]byte) {
	V := Y
	for i := 0; i < 128; i++ {
		if (X[i/8]>>(7-uint(i%8)))&1 == 1 {
			for j := 0; j < 16; j++ {
				Z[j] ^= V[j]
			}
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

func ghash(H [16]byte, A, C []byte) [16]byte {
	var Y, block [16]byte
	for i := 0; i < len(A); i += 16 {
		copy(block[:], A[i:min(i+16, len(A))])
		for j := 0; j < 16; j++ {
			Y[j] ^= block[j]
		}
		Y = gfMul(Y, H)
	}
	for i := 0; i < len(C); i += 16 {
		copy(block[:], C[i:min(i+16, len(C))])
		for j := 0; j < 16; j++ {
			Y[j] ^= block[j]
		}
		Y = gfMul(Y, H)
	}
	var lenBlock [16]byte
	binary.BigEndian.PutUint64(lenBlock[0:], uint64(len(A)*8))
	binary.BigEndian.PutUint64(lenBlock[8:], uint64(len(C)*8))
	for j := 0; j < 16; j++ {
		Y[j] ^= lenBlock[j]
	}
	Y = gfMul(Y, H)
	return Y
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	K1 := []byte("ZUC-KEY-12345678")
	K2 := []byte("ZUC-KEY-87654321")
	N1 := []byte("NONCE-ABC-123456")
	N2 := []byte("NONCE-XYZ-654321")
	H := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	P1 := []byte("this is the secret msg....") // 24 bytes
	aad := []byte("fixed-aad-A1")

	// Generate keystreams
	total := len(P1) + 16
	z1, _ := zuc.NewCipher(K1, N1)
	z2, _ := zuc.NewCipher(K2, N2)
	Za := make([]byte, total)
	Zb := make([]byte, total)
	z1.XORKeyStream(Za, Za)
	z2.XORKeyStream(Zb, Zb)
	Z0a := Za[:16]
	Z0b := Zb[:16]
	Z1a := Za[16:]
	Z1b := Zb[16:]

	// Compute C
	P2 := xor(P1, xor(Z1a, Z1b))
	C1 := xor(P1, Z1a)
	C2 := xor(P2, Z1b)

	// Compute GHASH
	Y1 := ghash(H, aad, C1)
	diffZ0 := xor(Z0a, Z0b)
	Y2 := [16]byte{}
	for i := 0; i < 16; i++ {
		Y2[i] = Y1[i] ^ diffZ0[i]
	}

	// Tag
	T1 := xor(Z0a, Y1[:])
	T2 := xor(Z0b, Y2[:])

	// Output
	fmt.Printf("P1: %s\nP2: %s\n", P1, P2)
	fmt.Println("C1 : ", hex.EncodeToString(C1))
	fmt.Println("C2 : ", hex.EncodeToString(C2))
	fmt.Println("T1 : ", hex.EncodeToString(T1))
	fmt.Println("T2 : ", hex.EncodeToString(T2))
	fmt.Println("AAD1:", aad)
	fmt.Println("C1 == C2?", hex.EncodeToString(C1) == hex.EncodeToString(C2))
	fmt.Println("T1 == T2?", hex.EncodeToString(T1) == hex.EncodeToString(T2))

	// Tambahkan di akhir fungsi main()

	// Verifikasi dekripsi C1, T1 dengan K1, N1
	zdec1, _ := zuc.NewCipher(K1, N1)
	stream1 := make([]byte, len(C1)+16)
	zdec1.XORKeyStream(stream1, stream1)
	Z0_1 := stream1[:16]
	Z1_1 := stream1[16:]
	P1_dec := xor(C1, Z1_1)
	Y1_check := ghash(H, aad, C1)
	T1_check := xor(Z0_1, Y1_check[:])
	fmt.Println("\n[+] Verifikasi K1, N1")
	fmt.Println("P1_dec:", string(P1_dec))
	fmt.Println("T1 verifikasi:", hex.EncodeToString(T1_check))
	fmt.Println("Tag cocok:", bytes.Equal(T1, T1_check))

	// Verifikasi dekripsi C2, T2 dengan K2, N2
	zdec2, _ := zuc.NewCipher(K2, N2)
	stream2 := make([]byte, len(C2)+16)
	zdec2.XORKeyStream(stream2, stream2)
	Z0_2 := stream2[:16]
	Z1_2 := stream2[16:]
	P2_dec := xor(C2, Z1_2)
	Y2_check := ghash(H, aad, C2)
	T2_check := xor(Z0_2, Y2_check[:])
	fmt.Println("\n[+] Verifikasi K2, N2")
	fmt.Println("P2_dec:", string(P2_dec))
	fmt.Println("T2 verifikasi:", hex.EncodeToString(T2_check))
	fmt.Println("Tag cocok:", bytes.Equal(T2, T2_check))

}
