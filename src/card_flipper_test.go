package main

import (
	"bytes"
	"crypto/des"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Frames from Proxmark3's HIDPack(..., preamble=true), i.e. what
// `lf hid sim/clone -w <format>` transmits.
func TestPackWiegandMatchesProxmark(t *testing.T) {
	tests := []struct {
		format        string
		fc, cn        uint64
		length        int
		top, mid, bot uint32
	}{
		{"H10301", 123, 4567, 26, 0, 0x20, 0x06f623ae},
		{"H10301", 118, 1603, 26, 0, 0x20, 0x06ec0c86},
		{"C1k35s", 118, 1603, 35, 0, 0x2e, 0x0ec00c87},
		{"C1k48s", 118, 1603, 48, 0, 0x14000, 0x76000c86},
		{"H10304", 65535, 524287, 37, 0, 0xf, 0xffffffff},
		{"C1k48s", 4194303, 8388607, 48, 0, 0x1bfff, 0xffffffff},
		{"H800002", 16383, 1073741823, 46, 0x09e00000, 0x5fff, 0xffffffff},
		{"Avig56", 1048575, 4194303, 56, 0x09e00000, 0x017ffff8, 0x007fffff},
		{"ind27", 100, 200, 27, 0, 0x20, 0x081900c8},
		{"S12906", 255, 16777215, 36, 0, 0x37, 0xf9ffffff},
		{"2804W", 1, 1, 28, 0, 0x20, 0x12010002},
	}
	for _, tt := range tests {
		m, err := packWiegand(tt.format, tt.fc, tt.cn)
		if err != nil {
			t.Fatalf("%s: %v", tt.format, err)
		}
		addHIDHeader(&m)
		if m.Length != tt.length || m.Top != tt.top || m.Mid != tt.mid || m.Bot != tt.bot {
			t.Errorf("%s FC %d CN %d = %d %08x %08x %08x, want %d %08x %08x %08x",
				tt.format, tt.fc, tt.cn, m.Length, m.Top, m.Mid, m.Bot, tt.length, tt.top, tt.mid, tt.bot)
		}
	}

	if _, err := packWiegand("H10301", 256, 1); err == nil {
		t.Error("H10301 accepted FC 256")
	}
}

// hidProxKeySize mirrors the Flipper's protocol_hid_generic_decode_protocol_size.
func hidProxKeySize(data []byte) int {
	bit := func(i int) bool { return data[i/8]&(0x80>>(i%8)) != 0 }
	for i := 0; i < 6; i++ {
		if bit(i) {
			return 44 - i - 1
		}
	}
	if !bit(6) {
		return 37
	}
	size := 36
	for i := 7; !bit(i) && size >= 26; i++ {
		size--
	}
	if size < 26 {
		return 0
	}
	return size
}

func TestHIDProxFramesDecodeOnFlipper(t *testing.T) {
	for bitLength, format := range hidFormatByBitLength {
		if bitLength > 37 || format == "H10301" {
			continue
		}
		f := wiegandFormats[format]
		file, err := hidFlipperFile("t", format, f.MaxFC/3, f.MaxCN/5)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(file.Content, "Key type: HIDProx\n") {
			t.Fatalf("%s: not exported as HIDProx:\n%s", format, file.Content)
		}
		m, _ := packWiegand(format, f.MaxFC/3, f.MaxCN/5)
		keyType, data := hidTransportData(m)
		if keyType != "HIDProx" || len(data) != 6 {
			t.Fatalf("%s: got %s with %d bytes", format, keyType, len(data))
		}
		if got := hidProxKeySize(data); got != bitLength {
			t.Errorf("%s: Flipper would decode a %d-bit key, want %d", format, got, bitLength)
		}
		var v uint64
		for _, b := range data {
			v = v<<8 | uint64(b)
		}
		if key := (v >> 4) & (1<<bitLength - 1); key != m.value() {
			t.Errorf("%s: key bits %x, want %x", format, key, m.value())
		}
	}
}

func TestHIDLongFormatsMatchProxmarkLongFrame(t *testing.T) {
	// `lf hid sim` long format sends the low 28 bits of hi2 (header 0x09E00000
	// becomes 9E00000), then hi and lo; the Flipper data adds 4 pad bits
	tests := []struct {
		format string
		fc, cn uint64
		want   string
	}{
		{"H800002", 16383, 1073741823, "9E 00 00 00 00 05 FF FF FF FF FF F0"},
		{"C1k48s", 4194303, 8388607, "00 00 00 00 00 1B FF FF FF FF FF F0"},
		{"Avig56", 1048575, 4194303, "9E 00 00 00 17 FF FF 80 07 FF FF F0"},
	}
	for _, tt := range tests {
		m, err := packWiegand(tt.format, tt.fc, tt.cn)
		if err != nil {
			t.Fatal(err)
		}
		keyType, data := hidTransportData(m)
		if keyType != "HIDExt" || flipperHex(data) != tt.want {
			t.Errorf("%s: %s %s, want HIDExt %s", tt.format, keyType, flipperHex(data), tt.want)
		}
	}
}

func TestH10301RFIDFile(t *testing.T) {
	file, err := buildFlipperFile("prox", 26, 123, 4567, "", "")
	if err != nil {
		t.Fatal(err)
	}
	want := "Filetype: Flipper RFID key\nVersion: 1\nKey type: H10301\nData: 7B 11 D7\n"
	if file.Content != want {
		t.Errorf("content:\n%s\nwant:\n%s", file.Content, want)
	}
	if file.Folder != "lfrfid" || file.Name != "prox_H10301_123_4567.rfid" {
		t.Errorf("path %s/%s", file.Folder, file.Name)
	}
	if file.CLI != "rfid emulate H10301 7B11D7" {
		t.Errorf("CLI %q", file.CLI)
	}
}

func TestEM4100RFIDFile(t *testing.T) {
	file, err := buildFlipperFile("em", 32, 0, 0, "5800856402", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(file.Content, "Key type: EM4100\nData: 58 00 85 64 02\n") {
		t.Errorf("content:\n%s", file.Content)
	}
	if _, err := buildFlipperFile("em", 32, 0, 0, "58008564", ""); err == nil {
		t.Error("accepted a 4-byte EM4100 ID")
	}
}

// awidFromProxmark turns a getAWIDBits() stream (preamble + 88 bits with an odd
// parity bit after every 3) into Flipper AWID data, as the Flipper decoder does.
func awidFromProxmark(t *testing.T, stream string) []byte {
	t.Helper()
	var w bitWriter
	for i := 8; i < 96; i += 4 {
		ones := 0
		for j := 0; j < 4; j++ {
			ones += int(stream[i+j] - '0')
		}
		if ones%2 != 1 {
			t.Fatalf("group at %d is not odd parity", i)
		}
		for j := 0; j < 3; j++ {
			w.write(uint64(stream[i+j]-'0'), 1)
		}
	}
	return w.bytes(9)
}

func TestAWIDMatchesProxmark(t *testing.T) {
	tests := []struct {
		bitLength int
		fc, cn    uint64
		stream    string
	}{
		{26, 123, 4567, "000000010001110110110111110111010010000111100100111000010001000100010001000100010001000100010001"},
		{50, 65535, 8388607, "000000010010100010001110111011101110111010000001000101111110111011101110111011101110000100010001"},
	}
	for _, tt := range tests {
		got, err := awidFlipperData(tt.bitLength, tt.fc, tt.cn)
		if err != nil {
			t.Fatal(err)
		}
		if want := awidFromProxmark(t, tt.stream); !bytes.Equal(got, want) {
			t.Errorf("AWID %d: %s, want %s", tt.bitLength, flipperHex(got), flipperHex(want))
		}
	}
	// The Flipper shows FC/CN for 26-bit AWID from these bit positions
	data, _ := awidFlipperData(26, 123, 4567)
	var w bitWriter
	w.bits = nil
	for i := 0; i < 72; i++ {
		w.write(uint64(data[i/8]>>(7-i%8))&1, 1)
	}
	field := func(start, n int) (v uint64) {
		for i := start; i < start+n; i++ {
			v = v<<1 | uint64(w.bits[i])
		}
		return v
	}
	if field(0, 8) != 26 || field(9, 8) != 123 || field(17, 16) != 4567 {
		t.Errorf("AWID fields len=%d fc=%d cn=%d", field(0, 8), field(9, 8), field(17, 16))
	}
}

// indalaFromRaw maps a 64-bit Indala frame to Flipper Indala26 data, as the
// Flipper's decoder does (frame bits 33-59 and 62-63).
func indalaFromRaw(t *testing.T, raw []byte) []byte {
	t.Helper()
	get := func(i int) uint64 { return uint64(raw[i/8]>>(7-i%8)) & 1 }
	var w bitWriter
	for i := 33; i <= 59; i++ {
		w.write(get(i), 1)
	}
	w.write(get(62), 1)
	w.write(get(63), 1)
	return w.bytes(4)
}

func TestIndala26(t *testing.T) {
	tests := []struct {
		fc, cn uint64
		want   []byte
	}{
		// Flipper firmware unit test key
		{186, 46902, []byte{0x3B, 0x73, 0x64, 0xA8}},
		// `lf indala sim --raw a0000000c2c436c1` from the Proxmark3 help
		{132, 20827, indalaFromRaw(t, mustHex(t, "a0000000c2c436c1"))},
		// Proxmark3 getIndalaBits(123, 4567)
		{123, 4567, indalaFromRaw(t, mustHex(t, "a0000000e1cbf231"))},
	}
	for _, tt := range tests {
		got, err := indala26FlipperData(tt.fc, tt.cn)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, tt.want) {
			t.Errorf("FC %d CN %d: %s, want %s", tt.fc, tt.cn, flipperHex(got), flipperHex(tt.want))
		}
	}
	if _, err := indala26FlipperData(256, 1); err == nil {
		t.Error("accepted FC 256")
	}
}

func TestIndala27IsHIDProx(t *testing.T) {
	file, err := buildFlipperFile("indala", 27, 100, 200, "", "")
	if err != nil {
		t.Fatal(err)
	}
	// ind27 FC 100 CN 200 with HID header is 020 081900C8, left-aligned in 48 bits
	if !strings.Contains(file.Content, "Key type: HIDProx\nData: 02 00 81 90 0C 80\n") {
		t.Errorf("content:\n%s", file.Content)
	}
	if _, err := buildFlipperFile("indala", 28, 1, 1, "", ""); err == nil {
		t.Error("accepted Indala 28-bit")
	}
}

func TestIclassHash0(t *testing.T) {
	// testCryptedCSN vectors from Proxmark3 loclass/ikeys.c
	tests := map[uint64]string{
		0x0102030405060708: "0bdd6512073c460a",
		0x1020304050607080: "0208211405f3381f",
		0x1122334455667788: "2bee256d40ac1f3a",
		0xabcdabcdabcdabcd: "a91c9ec66f7da592",
		0xbcdabcdabcdabcda: "79ca5796a474e19b",
		0xcdabcdabcdabcdab: "a8901b9f7ec76da4",
		0xdabcdabcdabcdabc: "357aa8e0979a5b8d",
		0x21ba6565071f9299: "34e80f88d5cf39ea",
		0x14e2adfc5bb7e134: "6ac90c6508bd9ea3",
	}
	for in, want := range tests {
		if got := hex.EncodeToString(iclassHash0(in)); got != want {
			t.Errorf("hash0(%016x) = %s, want %s", in, got, want)
		}
	}
}

func TestIclassDiversifyKey(t *testing.T) {
	// {CSN, Kd} with the standard key, from Proxmark3 loclass/ikeys.c testcases
	tests := [][2]string{
		{"8BAC601F53B8ED11", "0204060801030507"},
		{"AE51E562E79A9939", "0402060801030507"},
		{"9B21E4316A002962", "0604020801030507"},
		{"36 73 DF C1 1B 98 A8 1D", "0102030405060807"},
		{"CEE0B31B41EB1512", "0102030406050807"},
		// the dump card_simulators.go builds for `hf iclass sim`
		{"28668B15FEFF12E0", "843F766755B8DBCE"},
	}
	for _, tt := range tests {
		got := iclassDiversifyKey(mustHex(t, tt[0]), iclassStandardKey)
		if !bytes.Equal(got, mustHex(t, tt[1])) {
			t.Errorf("Kd(%s) = %X, want %s", tt[0], got, tt[1])
		}
	}
}

func TestIclassTransportEncryption(t *testing.T) {
	plain := mustHex(t, "0000000006F623AE")
	// 2-key 3DES is E(K1) D(K2) E(K1)
	k1, _ := des.NewCipher(iclassTransportKey[:8])
	k2, _ := des.NewCipher(iclassTransportKey[8:])
	want := make([]byte, 8)
	k1.Encrypt(want, plain)
	k2.Decrypt(want, want)
	k1.Encrypt(want, want)
	if got := iclassEncryptBlock(plain); !bytes.Equal(got, want) {
		t.Errorf("got %X, want %X", got, want)
	}
	// Blocks 8 and 9 of legacy iCLASS dumps: an empty PIN block under the transport key
	if got := iclassEncryptBlock(make([]byte, 8)); !bytes.Equal(got, mustHex(t, "2AD4C8211F996871")) {
		t.Errorf("encrypted zero block %X", got)
	}
}

func TestIclassPicopassFile(t *testing.T) {
	file, err := buildFlipperFile("iclass", 26, 123, 4567, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if file.Folder != "apps_data/picopass" || file.Name != "iclass_H10301_123_4567.picopass" {
		t.Errorf("path %s/%s", file.Folder, file.Name)
	}
	lines := strings.Split(strings.TrimSpace(file.Content), "\n")
	if lines[0] != "Filetype: Flipper Picopass device" || lines[1] != "Version: 1" {
		t.Errorf("header %q", lines[:2])
	}
	if lines[2] != "Credential: 00 00 00 00 02 F6 23 AE" {
		t.Errorf("credential %q", lines[2])
	}
	blocks := map[int][]byte{}
	for _, line := range lines[4:] {
		var n int
		parts := strings.SplitN(line, ": ", 2)
		if _, err := fmt.Sscanf(parts[0], "Block %d", &n); err != nil {
			t.Fatalf("bad line %q", line)
		}
		blocks[n] = mustHex(t, parts[1])
	}
	if len(blocks) != 18 {
		t.Fatalf("%d blocks, want 18 (config block app limit 0x12)", len(blocks))
	}
	csn := blocks[0]
	if !bytes.Equal(csn[4:], []byte{0xFE, 0xFF, 0x12, 0xE0}) {
		t.Errorf("CSN %X outside the HID range", csn)
	}
	if !bytes.Equal(blocks[3], iclassDiversifyKey(csn, iclassStandardKey)) {
		t.Error("block 3 is not the diversified key for the CSN")
	}
	if !bytes.Equal(blocks[6], []byte{0x03, 0x03, 0x03, 0x03, 0x00, 0x03, 0xE0, 0x17}) {
		t.Errorf("block 6 %X", blocks[6])
	}
	// Block 7 decrypts to the sentinel-marked Wiegand frame, as legacy readers see it
	key := append(append([]byte{}, iclassTransportKey...), iclassTransportKey[:8]...)
	c, _ := des.NewTripleDESCipher(key)
	plain := make([]byte, 8)
	c.Decrypt(plain, blocks[7])
	if !bytes.Equal(plain, mustHex(t, "0000000006F623AE")) {
		t.Errorf("block 7 decrypts to %X", plain)
	}
	c.Decrypt(plain, blocks[8])
	if !bytes.Equal(plain, make([]byte, 8)) {
		t.Errorf("block 8 decrypts to %X", plain)
	}

	other, _ := buildFlipperFile("iclass", 26, 123, 4568, "", "")
	if strings.Contains(other.Content, flipperHex(csn)) {
		t.Error("different credentials share a CSN")
	}
}

func TestIclassLongFormat(t *testing.T) {
	file, err := buildFlipperFile("iclass", 48, 118, 1603, "", "")
	if err != nil {
		t.Fatal(err)
	}
	// C1k48s FC 118 CN 1603 is 4000 76000C86; the sentinel goes at bit 48
	if !strings.Contains(file.Content, "Credential: 00 00 40 00 76 00 0C 86\n") {
		t.Errorf("content:\n%s", file.Content)
	}
}

func TestMifareNFCFile(t *testing.T) {
	file, err := buildFlipperFile("mifare", 0, 0, 0, "", "5AF70D9D")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Filetype: Flipper NFC device\nVersion: 4\n",
		"Device type: Mifare Classic\n",
		"UID: 5A F7 0D 9D\n",
		"ATQA: 00 04\nSAK: 08\n",
		"Mifare Classic type: 1K\nData format version: 2\n",
		"Block 0: 5A F7 0D 9D 3D 08 04 00 62 63 64 65 66 67 68 69\n",
		"Block 1: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n",
		"Block 3: FF FF FF FF FF FF FF 07 80 69 FF FF FF FF FF FF\n",
		"Block 63: FF FF FF FF FF FF FF 07 80 69 FF FF FF FF FF FF\n",
	} {
		if !strings.Contains(file.Content, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(file.Content, "Block 64:") {
		t.Error("more than 64 blocks")
	}

	seven, err := buildFlipperFile("mifare", 0, 0, 0, "", "04 A1 B2 C3 D4 E5 F6")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(seven.Content, "ATQA: 00 44\n") || !strings.Contains(seven.Content, "Block 0: 04 A1 B2 C3 D4 E5 F6 08 44 00 62 63 64 65 66 67\n") {
		t.Errorf("7-byte UID:\n%s", seven.Content)
	}
	if _, err := buildFlipperFile("mifare", 0, 0, 0, "", "5AF70D"); err == nil {
		t.Error("accepted a 3-byte UID")
	}
}

func TestPIVNFCFile(t *testing.T) {
	file, err := buildFlipperFile("piv", 0, 0, 0, "", "5AF70D9D")
	if err != nil {
		t.Fatal(err)
	}
	want := "Device type: ISO14443-4A\n# UID is common for all formats\nUID: 5A F7 0D 9D\n" +
		"# ISO14443-3A specific data\nATQA: 03 04\nSAK: 20\n" +
		"# ISO14443-4A specific data\nT0: 75\nTA(1): 77\nTB(1): 81\nTC(1): 02\nT1...Tk: 80\n"
	if !strings.HasSuffix(file.Content, want) {
		t.Errorf("content:\n%s", file.Content)
	}
}

func TestEveryCardTypeExports(t *testing.T) {
	cases := []struct {
		cardType  string
		bitLength int
	}{
		{"prox", 26}, {"prox", 28}, {"prox", 30}, {"prox", 31}, {"prox", 33}, {"prox", 34},
		{"prox", 35}, {"prox", 36}, {"prox", 37}, {"prox", 46}, {"prox", 48},
		{"iclass", 26}, {"iclass", 30}, {"iclass", 33}, {"iclass", 34}, {"iclass", 35},
		{"iclass", 36}, {"iclass", 37}, {"iclass", 46}, {"iclass", 48},
		{"awid", 26}, {"awid", 50}, {"indala", 26}, {"indala", 27}, {"indala", 29}, {"avigilon", 56},
	}
	for _, c := range cases {
		if _, err := buildFlipperFile(c.cardType, c.bitLength, 1, 1, "", ""); err != nil {
			t.Errorf("%s %d: %v", c.cardType, c.bitLength, err)
		}
	}
}

func TestExportWritesSDLayout(t *testing.T) {
	dir := t.TempDir()
	stdout := os.Stdout
	devNull, _ := os.Open(os.DevNull)
	os.Stdout = devNull
	SetStatusWriter(&bytes.Buffer{})
	exportFlipperFile("prox", 26, 123, 4567, "", "", dir)
	os.Stdout = stdout
	devNull.Close()

	got, err := os.ReadFile(filepath.Join(dir, "lfrfid", "prox_H10301_123_4567.rfid"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "Key type: H10301\n") {
		t.Errorf("file:\n%s", got)
	}
}
