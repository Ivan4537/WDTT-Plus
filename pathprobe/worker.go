package pathprobe

import (
	"fmt"
	"strconv"
	"strings"
)

// Worker identifies a replaceable path within an authenticated transport session.
// It is not an account or credential identifier. The bound keeps server state
// finite even when the client supplies arbitrary path numbers.
type Worker struct {
	Slot    uint32
	Attempt uint64
}

func (w Worker) Valid() bool    { return w.Slot > 0 && w.Slot <= 4096 && w.Attempt > 0 }
func (w Worker) String() string { return fmt.Sprintf("W1:%d:%d", w.Slot, w.Attempt) }
func ParseWorker(s string) (Worker, bool) {
	p := strings.Split(s, ":")
	if len(p) != 3 || p[0] != "W1" {
		return Worker{}, false
	}
	slot, e1 := strconv.ParseUint(p[1], 10, 32)
	attempt, e2 := strconv.ParseUint(p[2], 10, 64)
	w := Worker{Slot: uint32(slot), Attempt: attempt}
	return w, e1 == nil && e2 == nil && w.Valid()
}
