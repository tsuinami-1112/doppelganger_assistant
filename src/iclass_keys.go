package main

import (
	"crypto/des"
)

// HID's standard iCLASS application key (AEA684A6DAB23278) in the DES form the
// Flipper Picopass app uses; DES ignores the parity bits that differ.
var iclassStandardKey = []byte{0xAF, 0xA7, 0x85, 0xA7, 0xDA, 0xB3, 0x33, 0x78}

// 2-key 3DES transport key that legacy readers use to decrypt blocks 7-9,
// as embedded in the Flipper Picopass app.
var iclassTransportKey = []byte{
	0xB4, 0x21, 0x2C, 0xCA, 0xB7, 0xED, 0x21, 0x0F,
	0x7B, 0x93, 0xD4, 0x59, 0x39, 0xC7, 0xDD, 0x36,
}

// iclassEncryptBlock encrypts one block with the transport key (3DES EDE2).
func iclassEncryptBlock(plain []byte) []byte {
	key := append(append([]byte{}, iclassTransportKey...), iclassTransportKey[:8]...)
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, 8)
	block.Encrypt(out, plain)
	return out
}

// iclassDiversifyKey computes a card's diversified key Kd from its CSN:
// hash0(DES_key(CSN)). Ported from loclass (optimized_ikeys.c).
func iclassDiversifyKey(csn, key []byte) []byte {
	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}
	crypted := make([]byte, 8)
	block.Encrypt(crypted, csn)
	var c uint64
	for _, b := range crypted {
		c = c<<8 | uint64(b)
	}
	return iclassHash0(c)
}

var iclassPi = [35]uint8{
	0x0F, 0x17, 0x1B, 0x1D, 0x1E, 0x27, 0x2B, 0x2D, 0x2E,
	0x33, 0x35, 0x39, 0x36, 0x3A, 0x3C, 0x47, 0x4B, 0x4D,
	0x4E, 0x53, 0x55, 0x56, 0x59, 0x5A, 0x5C, 0x63, 0x65,
	0x66, 0x69, 0x6A, 0x6C, 0x71, 0x72, 0x74, 0x78,
}

// The diversification works on eight 6-bit values z0..z7 packed into the low
// 48 bits of a uint64, z0 most significant.
func sixBitByte(c uint64, n int) uint8 {
	return uint8(c>>(42-6*n)) & 0x3F
}

func pushSixBitByte(c *uint64, z uint8, n int) {
	shift := uint(42 - 6*n)
	*c &^= 0x3F << shift
	*c |= uint64(z&0x3F) << shift
}

func swapZValues(c uint64) uint64 {
	var z uint64
	for i := 0; i < 8; i++ {
		pushSixBitByte(&z, sixBitByte(c, i), 7-i)
	}
	return z | c&0xFFFF000000000000
}

func iclassCk(i, j int, z uint64) uint64 {
	if i == 1 && j == -1 {
		return z
	}
	if j == -1 {
		return iclassCk(i-1, i-2, z)
	}
	if sixBitByte(z, i) == sixBitByte(z, j) {
		var nz uint64
		for c := 0; c < 4; c++ {
			if c == i {
				pushSixBitByte(&nz, uint8(j), c)
			} else {
				pushSixBitByte(&nz, sixBitByte(z, c), c)
			}
		}
		return iclassCk(i, j-1, nz)
	}
	return iclassCk(i, j-1, z)
}

func iclassCheck(z uint64) uint64 {
	ck1 := iclassCk(3, 2, z) & 0xFFFFFF000000
	ck2 := iclassCk(3, 2, z<<24) & 0xFFFFFF000000
	return ck1 | ck2>>24
}

// iclassPermute takes the bits of p from least significant up; a 1 emits
// z[l]+1 and a 0 emits z[r], giving eight 6-bit values.
func iclassPermute(p uint8, z uint64) uint64 {
	var out uint64
	l, r := 0, 4
	for i := 0; i < 8; i++ {
		var v uint8
		if (p>>i)&1 == 1 {
			v = sixBitByte(z, l) + 1
			l++
		} else {
			v = sixBitByte(z, r)
			r++
		}
		out = out<<6 | uint64(v&0x3F)
	}
	return out
}

func iclassHash0(c uint64) []byte {
	c = swapZValues(c)
	x := uint8(c >> 56)
	y := uint8(c >> 48)

	var zP uint64
	for n := 0; n < 4; n++ {
		zn := sixBitByte(c, n)
		zn4 := sixBitByte(c, n+4)
		pushSixBitByte(&zP, zn%uint8(63-n)+uint8(n), n)
		pushSixBitByte(&zP, zn4%uint8(64-n)+uint8(n), n+4)
	}

	zCaret := iclassCheck(zP)
	p := iclassPi[x%35]
	if x&1 == 1 {
		p = ^p
	}
	zTilde := iclassPermute(p, zCaret)

	k := make([]byte, 8)
	for i := 0; i < 8; i++ {
		k[i] = (y << (7 - i)) & 0x80
		zt := sixBitByte(zTilde, i) << 1
		pi := (p >> i) & 1
		if k[i] != 0 {
			k[i] |= ^zt & 0x7E
			k[i] |= pi
			k[i]++
		} else {
			k[i] |= zt & 0x7E
			k[i] |= ^pi & 1
		}
	}
	return k
}
