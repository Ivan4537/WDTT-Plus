// Package pathprobe describes an opt-in, authenticated per-path delivery report.
// It must only be used inside an admitted DTLS session. It neither authenticates
// traffic nor replaces WireGuard replay protection.
package pathprobe

import "encoding/binary"

const (
	Header          = 16
	MaxPayload      = 1440
	Data       byte = 1
	Probe      byte = 2
	Bypass     byte = 4
)

func Frame(dst, payload []byte, kind byte, seq uint64) []byte {
	if (kind != Data && kind != Probe && kind != Bypass) || len(payload) > MaxPayload || seq == ^uint64(0) {
		return nil
	}
	n := Header + len(payload)
	if cap(dst) < n {
		dst = make([]byte, n)
	} else {
		dst = dst[:n]
		clear(dst[:Header])
	}
	copy(dst, "WDU2")
	dst[4] = kind
	binary.BigEndian.PutUint64(dst[8:16], seq)
	copy(dst[Header:], payload)
	return dst
}
func Parse(p []byte) (kind byte, seq uint64, payload []byte, ok bool) {
	if len(p) < Header || len(p) > Header+MaxPayload || string(p[:4]) != "WDU2" || (p[4] != Data && p[4] != Probe && p[4] != Bypass) || p[5] != 0 || p[6] != 0 || p[7] != 0 {
		return
	}
	seq = binary.BigEndian.Uint64(p[8:16])
	if seq == ^uint64(0) {
		return
	}
	return p[4], seq, p[Header:], true
}
func Ack(expected, received uint64) []byte {
	p := make([]byte, 24)
	copy(p, "WDA2")
	binary.BigEndian.PutUint64(p[8:16], expected)
	binary.BigEndian.PutUint64(p[16:24], received)
	return p
}
func ParseAck(p []byte) (expected, received uint64, ok bool) {
	if len(p) != 24 || string(p[:4]) != "WDA2" || binary.BigEndian.Uint32(p[4:8]) != 0 {
		return
	}
	expected = binary.BigEndian.Uint64(p[8:16])
	received = binary.BigEndian.Uint64(p[16:24])
	return expected, received, received <= expected
}

// Receipt is a bounded deduplicator, owned by one caller or protected by a lock.
// Reports are cumulative so losing a report cannot masquerade as data loss.
// Gaps count only within a path, never between unrelated paths.
type Receipt struct {
	Expected, Received uint64
	seen               [256]uint64
}

func (r *Receipt) Observe(seq uint64) bool {
	if seq == ^uint64(0) || (seq < r.Expected && r.Expected-seq > uint64(len(r.seen))) {
		return false
	}
	slot := seq % uint64(len(r.seen))
	if r.seen[slot] == seq+1 {
		return false
	}
	r.seen[slot] = seq + 1
	r.Received++
	if seq >= r.Expected {
		r.Expected = seq + 1
	}
	return true
}
