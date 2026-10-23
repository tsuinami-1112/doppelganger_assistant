package main

import (
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strings"
)

// Flipper Zero export: builds the files the Flipper's own apps load from its
// SD card (125 kHz RFID, NFC and the PicoPass app) so a credential can be
// copied over and emulated without a Proxmark3.

const flipperDefaultDir = "doppelganger_flipper"

// flipperFile is one file for the Flipper's SD card.
type flipperFile struct {
	Folder  string // folder under /ext on the SD card
	Name    string
	Content string
	Emulate string   // where to emulate it on the Flipper
	CLI     string   // Flipper CLI command that emulates it over USB, if any
	Notes   []string // anything worth knowing before using it
}

// Proxmark3 Wiegand format for each HID bit length this tool offers.
var hidFormatByBitLength = map[int]string{
	26: "H10301", 28: "2804W", 30: "ATSW30", 31: "ADT31", 33: "D10202", 34: "H10306",
	35: "C1k35s", 36: "S12906", 37: "H10304", 46: "H800002", 48: "C1k48s",
}

var iclassBitLengths = map[int]bool{26: true, 30: true, 33: true, 34: true, 35: true, 36: true, 37: true, 46: true, 48: true}

// buildFlipperFile returns the Flipper Zero file for a credential.
func buildFlipperFile(cardType string, bitLength, facilityCode, cardNumber int, hexData, uid string) (*flipperFile, error) {
	if facilityCode < 0 || cardNumber < 0 {
		return nil, fmt.Errorf("facility code and card number must not be negative")
	}
	fc, cn := uint64(facilityCode), uint64(cardNumber)

	switch cardType {
	case "prox":
		format, ok := hidFormatByBitLength[bitLength]
		if !ok {
			return nil, fmt.Errorf("unsupported bit length %d for Prox", bitLength)
		}
		return hidFlipperFile(fmt.Sprintf("prox_%s_%d_%d", format, fc, cn), format, fc, cn)
	case "avigilon":
		if bitLength != 56 {
			return nil, fmt.Errorf("unsupported bit length %d for Avigilon, only 56 is supported", bitLength)
		}
		return hidFlipperFile(fmt.Sprintf("avigilon_56_%d_%d", fc, cn), "Avig56", fc, cn)
	case "awid":
		data, err := awidFlipperData(bitLength, fc, cn)
		if err != nil {
			return nil, err
		}
		return rfidFlipperFile(fmt.Sprintf("awid_%d_%d_%d", bitLength, fc, cn), "AWID", data), nil
	case "indala":
		switch bitLength {
		case 26:
			data, err := indala26FlipperData(fc, cn)
			if err != nil {
				return nil, err
			}
			return rfidFlipperFile(fmt.Sprintf("indala_26_%d_%d", fc, cn), "Indala26", data), nil
		case 27, 29:
			// Same as the simulate path: `lf hid sim -w ind27/ind29`
			format := fmt.Sprintf("ind%d", bitLength)
			file, err := hidFlipperFile(fmt.Sprintf("indala_%d_%d_%d", bitLength, fc, cn), format, fc, cn)
			if err != nil {
				return nil, err
			}
			file.Notes = append(file.Notes, fmt.Sprintf("Indala %d-bit is emulated as HID Prox carrying the %s Wiegand layout, like `lf hid sim -w %s`", bitLength, format, format))
			return file, nil
		default:
			return nil, fmt.Errorf("unsupported bit length %d for Indala, supported: 26, 27, 29", bitLength)
		}
	case "em":
		if valid, msg := validateEM4100Hex(hexData); !valid {
			return nil, fmt.Errorf("%s", msg)
		}
		data, _ := hex.DecodeString(strings.TrimSpace(hexData))
		return rfidFlipperFile("em4100_"+strings.ToUpper(strings.TrimSpace(hexData)), "EM4100", data), nil
	case "iclass":
		if !iclassBitLengths[bitLength] {
			return nil, fmt.Errorf("unsupported bit length %d for iCLASS", bitLength)
		}
		return iclassFlipperFile(hidFormatByBitLength[bitLength], fc, cn)
	case "mifare":
		return mifareFlipperFile(uid)
	case "piv":
		return pivFlipperFile(uid)
	}
	return nil, fmt.Errorf("unsupported card type %q", cardType)
}

func rfidFlipperFile(name, keyType string, data []byte) *flipperFile {
	content := "Filetype: Flipper RFID key\n" +
		"Version: 1\n" +
		"Key type: " + keyType + "\n" +
		"Data: " + flipperHex(data) + "\n"
	return &flipperFile{
		Folder:  "lfrfid",
		Name:    name + ".rfid",
		Content: content,
		Emulate: "125 kHz RFID > Saved > " + name + " > Emulate",
		CLI:     fmt.Sprintf("rfid emulate %s %X", keyType, data),
	}
}

// hidFlipperFile packs an HID Prox credential the way `lf hid sim -w` sends it.
func hidFlipperFile(name, format string, fc, cn uint64) (*flipperFile, error) {
	m, err := packWiegand(format, fc, cn)
	if err != nil {
		return nil, err
	}
	if format == "H10301" {
		// The Flipper's native H10301 key; FC and CN without the parity bits
		return rfidFlipperFile(name, "H10301", []byte{byte(fc), byte(cn >> 8), byte(cn)}), nil
	}
	keyType, data := hidTransportData(m)
	return rfidFlipperFile(name, keyType, data), nil
}

// hidTransportData adds the HID header to a Wiegand frame and returns the
// Flipper key type and data that put the same frame on the air as a Proxmark3.
func hidTransportData(m wiegandMessage) (string, []byte) {
	addHIDHeader(&m)
	var w bitWriter
	if m.Mid > 0xFFF {
		// Long format: 28 header bits, then 64 bits (Proxmark's longFMT)
		w.write(uint64(m.Top&0x0FFFFFFF), 28)
		w.write(uint64(m.Mid), 32)
		w.write(uint64(m.Bot), 32)
		return "HIDExt", w.bytes(12)
	}
	w.write(uint64(m.Mid&0xFFF), 12)
	w.write(uint64(m.Bot), 32)
	return "HIDProx", w.bytes(6)
}

// awidFlipperData builds the Flipper AWID data: the format length, then the
// Wiegand frame with even/odd parity over its halves (Proxmark getAWIDBits).
func awidFlipperData(bitLength int, fc, cn uint64) ([]byte, error) {
	var fcBits, cnBits int
	switch bitLength {
	case 26:
		fcBits, cnBits = 8, 16
	case 50:
		fcBits, cnBits = 16, 32
	default:
		return nil, fmt.Errorf("unsupported bit length %d for AWID, supported: 26, 50", bitLength)
	}
	if fc >= 1<<fcBits || cn >= 1<<cnBits {
		return nil, fmt.Errorf("AWID %d-bit holds a %d-bit facility code and %d-bit card number", bitLength, fcBits, cnBits)
	}
	payload := fc<<cnBits | cn
	half := (fcBits + cnBits) / 2
	even := uint64(bitsOnes(payload>>half) & 1)
	odd := uint64(bitsOnes(payload&(1<<half-1))&1) ^ 1

	var w bitWriter
	w.write(uint64(bitLength), 8)
	w.write(even, 1)
	w.write(payload, fcBits+cnBits)
	w.write(odd, 1)
	return w.bytes(9), nil
}

// indala26FlipperData builds Flipper Indala26 data from FC/CN the same way
// the Flipper firmware converts FC/CN keys (lfrfid_dict_file.c): scrambled
// FC/CN bits, the Indala checksum and Wiegand parity.
func indala26FlipperData(fc, cn uint64) ([]byte, error) {
	if fc > 0xFF || cn > 0xFFFF {
		return nil, fmt.Errorf("Indala 26-bit holds an 8-bit facility code and 16-bit card number")
	}
	data := make([]byte, 4)
	set := func(pos int, v uint64) {
		if v&1 == 1 {
			data[pos/8] |= 0x80 >> (pos % 8)
		}
	}
	fcPositions := []int{24, 16, 11, 14, 15, 20, 6, 25}                           // FC bit 7..0
	cnPositions := []int{9, 12, 10, 7, 19, 3, 2, 18, 13, 0, 4, 21, 23, 26, 17, 8} // CN bit 15..0
	for i, p := range fcPositions {
		set(p, fc>>(7-i))
	}
	for i, p := range cnPositions {
		set(p, cn>>(15-i))
	}

	fcAndCard := fc<<16 | cn
	checksum := 0
	for _, b := range []uint{14, 12, 9, 8, 6, 5, 2, 0} {
		checksum += int(fcAndCard>>b) & 1
	}
	if checksum&1 == 1 {
		set(28, 1) // 01
	} else {
		set(27, 1) // 10
	}
	set(1, uint64(bitsOnes((fcAndCard>>12)&0xFFF)))
	set(5, uint64(bitsOnes(fcAndCard&0xFFF)+1))
	return data, nil
}

// iclassFlipperFile builds a legacy iCLASS (standard key) card for the
// Flipper PicoPass app, laid out like the app's own "Create" scene.
func iclassFlipperFile(format string, fc, cn uint64) (*flipperFile, error) {
	m, err := packWiegand(format, fc, cn)
	if err != nil {
		return nil, err
	}

	csn := iclassCSN(format, fc, cn)
	credential := beBytes(m.value())
	pacs := beBytes(m.value() | 1<<m.Length) // block 7 carries a sentinel bit above the Wiegand data
	ff := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	zero := make([]byte, 8)

	blocks := [][]byte{
		csn,
		{0x12, 0xFF, 0xFF, 0xFF, 0x7F, 0x1F, 0xFF, 0x3C}, // configuration, 18 blocks
		{0xFF, 0xFF, 0xFF, 0xFF, 0x05, 0xFE, 0xFF, 0xFF}, // e-purse
		iclassDiversifyKey(csn, iclassStandardKey),       // Kd
		ff, // Kc
		ff, // AIA
		{0x03, 0x03, 0x03, 0x03, 0x00, 0x03, 0xE0, 0x17}, // PACS config, 3DES
		iclassEncryptBlock(pacs),
		iclassEncryptBlock(zero),
		iclassEncryptBlock(zero),
	}
	for len(blocks) < 18 {
		blocks = append(blocks, ff)
	}

	var b strings.Builder
	b.WriteString("Filetype: Flipper Picopass device\n")
	b.WriteString("Version: 1\n")
	b.WriteString("Credential: " + flipperHex(credential) + "\n")
	b.WriteString("# Picopass blocks\n")
	for i, block := range blocks {
		fmt.Fprintf(&b, "Block %d: %s\n", i, flipperHex(block))
	}

	name := fmt.Sprintf("iclass_%s_%d_%d", format, fc, cn)
	return &flipperFile{
		Folder:  "apps_data/picopass",
		Name:    name + ".picopass",
		Content: b.String(),
		Emulate: "Apps > NFC > PicoPass > Saved > " + name + " > Emulate",
		Notes: []string{
			"Needs the PicoPass app from the Flipper Apps catalog",
			fmt.Sprintf("Legacy iCLASS with HID standard keys, CSN %X; readers set for Elite or SE/Seos keys will not accept it", csn),
		},
	}, nil
}

// iclassCSN derives a stable CSN per credential inside HID's CSN range
// (xx xx xx xx Fx FF 12 E0) so each exported card reads as a distinct card.
func iclassCSN(format string, fc, cn uint64) []byte {
	h := fnv.New32a()
	fmt.Fprintf(h, "%s:%d:%d", format, fc, cn)
	s := h.Sum32()
	return []byte{byte(s >> 24), byte(s >> 16), byte(s >> 8), byte(s), 0xFE, 0xFF, 0x12, 0xE0}
}

func mifareFlipperFile(uid string) (*flipperFile, error) {
	u, err := parseUID(uid)
	if err != nil {
		return nil, err
	}
	// ATQA as the file stores it (most significant byte first) and as block 0 does
	atqa, atqaBlock0 := []byte{0x00, 0x04}, []byte{0x04, 0x00}
	if len(u) == 7 {
		atqa, atqaBlock0 = []byte{0x00, 0x44}, []byte{0x44, 0x00}
	}

	block0 := append([]byte{}, u...)
	if len(u) == 4 {
		block0 = append(block0, u[0]^u[1]^u[2]^u[3])
	}
	block0 = append(block0, 0x08)
	block0 = append(block0, atqaBlock0...)
	for i := byte(0x62); len(block0) < 16; i++ {
		block0 = append(block0, i)
	}

	var b strings.Builder
	b.WriteString(nfcFileHeader("Mifare Classic", u))
	b.WriteString("# ISO14443-3A specific data\n")
	b.WriteString("ATQA: " + flipperHex(atqa) + "\n")
	b.WriteString("SAK: 08\n")
	b.WriteString("# Mifare Classic specific data\n")
	b.WriteString("Mifare Classic type: 1K\n")
	b.WriteString("Data format version: 2\n")
	b.WriteString("# Mifare Classic blocks, '??' means unknown data\n")
	trailer := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x80, 0x69, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	for i := 0; i < 64; i++ {
		block := make([]byte, 16)
		switch {
		case i == 0:
			block = block0
		case i%4 == 3:
			block = trailer
		}
		fmt.Fprintf(&b, "Block %d: %s\n", i, flipperHex(block))
	}

	name := fmt.Sprintf("mifare_%X", u)
	return &flipperFile{
		Folder:  "nfc",
		Name:    name + ".nfc",
		Content: b.String(),
		Emulate: "NFC > Saved > " + name + " > Emulate",
		Notes:   []string{"MIFARE Classic 1K with this UID, blank sectors and default keys (FFFFFFFFFFFF)"},
	}, nil
}

// pivFlipperFile mirrors `hf 14a sim -t 3`: an ISO14443-4A card answering
// with the UID, SAK 20 and a DESFire-style ATS.
func pivFlipperFile(uid string) (*flipperFile, error) {
	u, err := parseUID(uid)
	if err != nil {
		return nil, err
	}
	atqa := []byte{0x03, 0x04}
	if len(u) == 7 {
		atqa = []byte{0x03, 0x44}
	}

	var b strings.Builder
	b.WriteString(nfcFileHeader("ISO14443-4A", u))
	b.WriteString("# ISO14443-3A specific data\n")
	b.WriteString("ATQA: " + flipperHex(atqa) + "\n")
	b.WriteString("SAK: 20\n")
	b.WriteString("# ISO14443-4A specific data\n")
	b.WriteString("T0: 75\n")
	b.WriteString("TA(1): 77\n")
	b.WriteString("TB(1): 81\n")
	b.WriteString("TC(1): 02\n")
	b.WriteString("T1...Tk: 80\n")

	name := fmt.Sprintf("piv_%X", u)
	return &flipperFile{
		Folder:  "nfc",
		Name:    name + ".nfc",
		Content: b.String(),
		Emulate: "NFC > Saved > " + name + " > Emulate",
		Notes:   []string{"UID-only emulation, for readers that send the UID over Wiegand"},
	}, nil
}

func nfcFileHeader(deviceType string, uid []byte) string {
	return "Filetype: Flipper NFC device\n" +
		"Version: 4\n" +
		"# Device type can be ISO14443-3A, ISO14443-3B, ISO14443-4A, ISO14443-4B, ISO15693-3, FeliCa, NTAG/Ultralight, Mifare Classic, Mifare Plus, Mifare DESFire, SLIX, ST25TB, NTAG4xx, Type 4 Tag\n" +
		"Device type: " + deviceType + "\n" +
		"# UID is common for all formats\n" +
		"UID: " + flipperHex(uid) + "\n"
}

// parseUID accepts a 4 or 7 byte UID, with or without separators.
func parseUID(uid string) ([]byte, error) {
	clean := strings.NewReplacer(" ", "", ":", "", "-", "").Replace(strings.TrimSpace(uid))
	u, err := hex.DecodeString(clean)
	if err != nil || (len(u) != 4 && len(u) != 7) {
		return nil, fmt.Errorf("UID must be 4 or 7 bytes of hex (8 or 14 characters), got %q", uid)
	}
	return u, nil
}

// flipperHex formats bytes as the Flipper file format writes them: "0A 1B 2C".
func flipperHex(data []byte) string {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, " ")
}

func beBytes(v uint64) []byte {
	out := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		out[i] = byte(v)
		v >>= 8
	}
	return out
}

func bitsOnes(v uint64) int {
	n := 0
	for ; v != 0; v &= v - 1 {
		n++
	}
	return n
}

// bitWriter packs values most significant bit first.
type bitWriter struct {
	bits []byte
}

func (w *bitWriter) write(v uint64, n int) {
	for i := n - 1; i >= 0; i-- {
		w.bits = append(w.bits, byte(v>>uint(i))&1)
	}
}

func (w *bitWriter) bytes(size int) []byte {
	out := make([]byte, size)
	for i, bit := range w.bits {
		out[i/8] |= bit << (7 - uint(i%8))
	}
	return out
}

// exportFlipperFile writes the Flipper file under outDir, mirroring the SD
// card layout, and prints where it goes and how to emulate it.
func exportFlipperFile(cardType string, bitLength, facilityCode, cardNumber int, hexData, uid, outDir string) {
	file, err := buildFlipperFile(cardType, bitLength, facilityCode, cardNumber, hexData, uid)
	if err != nil {
		WriteStatusError("Flipper Zero export failed: %v", err)
		return
	}

	if outDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			WriteStatusError("Error getting home directory: %v", err)
			return
		}
		outDir = filepath.Join(homeDir, flipperDefaultDir)
	}
	localDir := filepath.Join(outDir, filepath.FromSlash(file.Folder))
	localPath := filepath.Join(localDir, file.Name)
	if err := os.MkdirAll(localDir, 0755); err != nil {
		WriteStatusError("Error creating %s: %v", localDir, err)
		return
	}
	if err := os.WriteFile(localPath, []byte(file.Content), 0644); err != nil {
		WriteStatusError("Error writing %s: %v", localPath, err)
		return
	}

	sdPath := "/ext/" + file.Folder + "/" + file.Name
	fmt.Println("\n|----------- FLIPPER ZERO -----------|")
	fmt.Printf("Saved:    %s\n", localPath)
	fmt.Printf("SD card:  %s\n", sdPath)
	fmt.Printf("Copy:     cp \"%s\" \"<SD card mount>/%s/\"\n", localPath, file.Folder)
	fmt.Printf("Emulate:  %s\n", file.Emulate)
	if file.CLI != "" {
		fmt.Printf("CLI:      %s\n", file.CLI)
	}
	for _, note := range file.Notes {
		fmt.Printf("Note:     %s\n", note)
	}
	fmt.Println()
	fmt.Print(file.Content)

	WriteStatusSuccess("Flipper Zero file saved: %s", localPath)
	WriteStatusInfo("Copy it to %s on the Flipper's SD card (card reader or qFlipper), then %s", sdPath, file.Emulate)
}
