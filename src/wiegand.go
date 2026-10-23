package main

import (
	"fmt"
	"math/bits"
)

// wiegandMessage mirrors Proxmark3's wiegand_message_t so packed credentials
// are bit-for-bit identical to what `lf hid clone/sim -w <format>` and
// `hf iclass encode -w <format>` produce. Bit position 0 is the first bit on
// the wire (the most significant bit of the frame).
type wiegandMessage struct {
	Length int
	Top    uint32
	Mid    uint32
	Bot    uint32
}

func (m *wiegandMessage) word(pos int) (*uint32, uint) {
	p := m.Length - pos - 1
	switch {
	case p > 63:
		return &m.Top, uint(p - 64)
	case p > 31:
		return &m.Mid, uint(p - 32)
	default:
		return &m.Bot, uint(p)
	}
}

func (m *wiegandMessage) bit(pos int) uint32 {
	if pos < 0 || pos >= m.Length {
		return 0
	}
	w, shift := m.word(pos)
	return (*w >> shift) & 1
}

func (m *wiegandMessage) setBit(pos int, value uint32) {
	if pos < 0 || pos >= m.Length {
		return
	}
	w, shift := m.word(pos)
	if value&1 == 1 {
		*w |= 1 << shift
	} else {
		*w &^= 1 << shift
	}
}

func (m *wiegandMessage) linearField(first, length int) uint64 {
	var v uint64
	for i := 0; i < length; i++ {
		v = v<<1 | uint64(m.bit(first+i))
	}
	return v
}

func (m *wiegandMessage) setLinearField(value uint64, first, length int) {
	for i := 0; i < length; i++ {
		m.setBit(first+i, uint32(value>>(length-i-1)))
	}
}

func (m *wiegandMessage) nonlinearField(positions []int) uint64 {
	var v uint64
	for _, p := range positions {
		v = v<<1 | uint64(m.bit(p))
	}
	return v
}

// value returns the frame as an integer; valid for frames of up to 64 bits.
func (m *wiegandMessage) value() uint64 {
	return uint64(m.Mid)<<32 | uint64(m.Bot)
}

func evenParity32(x uint32) uint32 { return uint32(bits.OnesCount32(x) & 1) }
func oddParity32(x uint32) uint32  { return evenParity32(x) ^ 1 }

// stepParity ports step_parity_check() used by the Avigilon 56-bit format.
func (m *wiegandMessage) stepParity(start, length int, even bool) bool {
	parity := even
	for i := start; i < start+length; i += 2 {
		parity = parity != ((m.bit(i) ^ m.bit(i+1)) == 1)
	}
	return parity
}

// wiegandFormat describes one Proxmark3 Wiegand format (see `wiegand list`).
type wiegandFormat struct {
	Name  string
	Bits  int
	MaxFC uint64
	MaxCN uint64
	pack  func(fc, cn uint64) wiegandMessage
}

// Ported from Proxmark3 client/src/wiegand_formats.c. Only the formats this
// tool offers are included; the limits are Proxmark's own.
var wiegandFormats = map[string]wiegandFormat{
	"H10301": {"H10301", 26, 0xFF, 0xFFFF, func(fc, cn uint64) wiegandMessage {
		m := wiegandMessage{Length: 26}
		m.Bot |= uint32(cn&0xFFFF) << 1
		m.Bot |= uint32(fc&0xFF) << 17
		m.Bot |= oddParity32((m.Bot >> 1) & 0xFFF)
		m.Bot |= evenParity32((m.Bot>>13)&0xFFF) << 25
		return m
	}},
	"ind27": {"ind27", 27, 0x1FFF, 0x3FFF, func(fc, cn uint64) wiegandMessage {
		m := wiegandMessage{Length: 27}
		m.setLinearField(fc, 0, 13)
		m.setLinearField(cn, 13, 14)
		return m
	}},
	"2804W": {"2804W", 28, 0xFF, 0x7FFF, func(fc, cn uint64) wiegandMessage {
		m := wiegandMessage{Length: 28}
		m.setLinearField(fc, 4, 8)
		m.setLinearField(cn, 12, 15)
		m.setBit(2, oddParity32(uint32(m.nonlinearField([]int{4, 5, 7, 8, 10, 11, 13, 14, 16, 17, 19, 20, 22, 23, 25, 26}))))
		m.setBit(0, evenParity32(uint32(m.linearField(1, 13))))
		m.setBit(27, oddParity32(uint32(m.linearField(0, 27))))
		return m
	}},
	"ind29": {"ind29", 29, 0x1FFF, 0xFFFF, func(fc, cn uint64) wiegandMessage {
		m := wiegandMessage{Length: 29}
		m.setLinearField(fc, 0, 13)
		m.setLinearField(cn, 13, 16)
		return m
	}},
	"ATSW30": {"ATSW30", 30, 0xFFF, 0xFFFF, func(fc, cn uint64) wiegandMessage {
		m := wiegandMessage{Length: 30}
		m.setLinearField(fc, 1, 12)
		m.setLinearField(cn, 13, 16)
		m.setBit(0, evenParity32(uint32(m.linearField(1, 12))))
		m.setBit(29, oddParity32(uint32(m.linearField(13, 16))))
		return m
	}},
	"ADT31": {"ADT31", 31, 0xF, 0x7FFFFF, func(fc, cn uint64) wiegandMessage {
		m := wiegandMessage{Length: 31}
		m.setLinearField(fc, 1, 4)
		m.setLinearField(cn, 5, 23)
		return m
	}},
	"D10202": {"D10202", 33, 0x7F, 0xFFFFFF, func(fc, cn uint64) wiegandMessage {
		m := wiegandMessage{Length: 33}
		m.setLinearField(fc, 1, 7)
		m.setLinearField(cn, 8, 24)
		m.setBit(0, evenParity32(uint32(m.linearField(1, 16))))
		m.setBit(32, oddParity32(uint32(m.linearField(16, 16))))
		return m
	}},
	"H10306": {"H10306", 34, 0xFFFF, 0xFFFF, func(fc, cn uint64) wiegandMessage {
		m := wiegandMessage{Length: 34}
		m.Bot |= uint32(cn&0xFFFF) << 1
		m.Bot |= uint32(fc&0x7FFF) << 17
		m.Mid |= uint32(fc&0x8000) >> 15
		m.Mid |= evenParity32((m.Mid&0x1)^(m.Bot&0xFFFE0000)) << 1
		m.Bot |= oddParity32(m.Bot & 0x0001FFFE)
		return m
	}},
	"C1k35s": {"C1k35s", 35, 0xFFF, 0xFFFFF, func(fc, cn uint64) wiegandMessage {
		m := wiegandMessage{Length: 35}
		m.Bot |= uint32(cn&0x000FFFFF) << 1
		m.Bot |= uint32(fc&0x000007FF) << 21
		m.Mid |= uint32(fc&0x00000800) >> 11
		m.Mid |= evenParity32((m.Mid&0x1)^(m.Bot&0xB6DB6DB6)) << 1
		m.Bot |= oddParity32((m.Mid & 0x3) ^ (m.Bot & 0x6DB6DB6C))
		m.Mid |= oddParity32((m.Mid&0x3)^m.Bot) << 2
		return m
	}},
	"S12906": {"S12906", 36, 0xFF, 0xFFFFFF, func(fc, cn uint64) wiegandMessage {
		m := wiegandMessage{Length: 36}
		m.setLinearField(fc, 1, 8)
		m.setLinearField(0, 9, 2) // issue level
		m.setLinearField(cn, 11, 24)
		m.setBit(0, oddParity32(uint32(m.linearField(1, 17))))
		m.setBit(35, oddParity32(uint32(m.linearField(17, 18))))
		return m
	}},
	"H10304": {"H10304", 37, 0xFFFF, 0x7FFFF, func(fc, cn uint64) wiegandMessage {
		m := wiegandMessage{Length: 37}
		m.setLinearField(fc, 1, 16)
		m.setLinearField(cn, 17, 19)
		m.setBit(0, evenParity32(uint32(m.linearField(1, 18))))
		m.setBit(36, oddParity32(uint32(m.linearField(18, 18))))
		return m
	}},
	"H800002": {"H800002", 46, 0x3FFF, 0x3FFFFFFF, func(fc, cn uint64) wiegandMessage {
		m := wiegandMessage{Length: 46}
		m.setLinearField(fc, 1, 14)
		m.setLinearField(cn, 15, 30)
		even := evenParity32((m.Bot >> 1) ^ (m.Mid & 0x1FFF))
		m.setBit(0, even)
		m.setBit(45, even^1)
		return m
	}},
	"C1k48s": {"C1k48s", 48, 0x3FFFFF, 0x7FFFFF, func(fc, cn uint64) wiegandMessage {
		m := wiegandMessage{Length: 48}
		m.Bot |= uint32(cn&0x007FFFFF) << 1
		m.Bot |= uint32(fc&0x000000FF) << 24
		m.Mid |= uint32(fc&0x003FFF00) >> 8
		m.Mid |= evenParity32((m.Mid&0x00001B6D)^(m.Bot&0xB6DB6DB6)) << 14
		m.Bot |= oddParity32((m.Mid & 0x000036DB) ^ (m.Bot & 0x6DB6DB6C))
		m.Mid |= oddParity32((m.Mid&0x00007FFF)^m.Bot) << 15
		return m
	}},
	"Avig56": {"Avig56", 56, 0xFFFFF, 0x3FFFFFFFF, func(fc, cn uint64) wiegandMessage {
		m := wiegandMessage{Length: 56}
		m.setLinearField(fc, 1, 20)
		m.setLinearField(cn, 21, 34)
		m.setBit(0, boolToBit(!m.stepParity(0, 28, true)))
		m.setBit(55, boolToBit(!m.stepParity(28, 28, false)))
		return m
	}},
}

func boolToBit(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// packWiegand packs FC/CN with the named Proxmark3 format, rejecting values
// the format cannot hold (Proxmark's validate_card_limit).
func packWiegand(format string, fc, cn uint64) (wiegandMessage, error) {
	f, ok := wiegandFormats[format]
	if !ok {
		return wiegandMessage{}, fmt.Errorf("unsupported Wiegand format %s", format)
	}
	if fc > f.MaxFC {
		return wiegandMessage{}, fmt.Errorf("facility code %d exceeds %s maximum of %d", fc, format, f.MaxFC)
	}
	if cn > f.MaxCN {
		return wiegandMessage{}, fmt.Errorf("card number %d exceeds %s maximum of %d", cn, format, f.MaxCN)
	}
	return f.pack(fc, cn), nil
}

// addHIDHeader ports Proxmark3's add_HID_header(): the sentinel and header
// bits that turn a Wiegand frame into an HID Prox transport frame.
func addHIDHeader(m *wiegandMessage) {
	switch {
	case m.Length == 48:
		m.Mid |= 1 << (m.Length - 32)
	case m.Length >= 64:
		m.Top |= 0x09e00000
		m.Top |= 1 << (m.Length - 64)
	case m.Length > 37:
		m.Top |= 0x09e00000
		m.Mid |= 1 << (m.Length - 32)
	case m.Length == 37:
		// No header bits on 37-bit cards
	case m.Length >= 32:
		m.Mid |= 0x20
		m.Mid |= 1 << (m.Length - 32)
	default:
		m.Mid |= 0x20
		m.Bot |= 1 << m.Length
	}
}
