package redact

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
)

// What the rules find in a text is remembered, as Scrub remembers what it
// makes of one. An agent sends its whole conversation on every turn, so
// nearly every string of a request was in the one before it, and every
// rule ran over all of it again: on a long conversation that was nearly
// all of the CPU masking took (BenchmarkMaskJSONTurn), most of it in the
// rules' patterns.
//
// Only the rules' spans are kept: where in the text each value is, its kind
// and its finder, nothing of the value. Everything after the rules still
// runs on every request (mask's maskRest): the local model, the values
// known before (sentKnownSpans, with its own memory), the filters, the
// user's allowed values and actions, and the placeholders put in. A value
// that became known since, a value the user allowed or warned of since, a
// placeholder whose value was let go (makeRoom): each is what a text with
// no memory would get, since none of it is remembered.
//
// The spans depend on the text and on the options the rules read
// (rulesPrint), and on the day: a birthday is a date over a year ago
// (dateOK). All three are in the key. A text shorter than ruleMemoMin costs
// less to read than to look up.
const (
	ruleMemoMin     = 256
	ruleMemoEntries = 1 << 16
	// ruleMemoBytes bounds what the spans take, counted as spanSize each
	ruleMemoBytes = 16 << 20
	spanSize      = 64
)

// ruleMemoOff turns the memory off: every text is read by the rules, as
// before it. A var for the tests, which compare the two.
var ruleMemoOff atomic.Bool

type ruleMemo struct {
	sync.Mutex
	// two generations, as scrubMemo keeps: when the newer is full it
	// becomes the older and the older goes, so what is in use stays and at
	// most twice the bounds are held
	cur, old map[[32]byte][]span
	bytes    int
	gets     atomic.Uint64
	hits     atomic.Uint64
}

var rulesMemo ruleMemo

// rulesPrint is what of o the rules read: the user's words and how they
// match, the user's rules, and which categories are on. Each one changed
// changes it, so a span found under other settings is never used again.
func rulesPrint(o Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%t\x00%t\x00%t\x00%t\x00", o.Secrets, o.Personal, o.WordsAnyCase, o.WordsWhole)
	for _, w := range o.Words {
		fmt.Fprintf(&b, "w%d:%s\x00", len(w), w)
	}
	if o.Secrets {
		for _, r := range o.Rules {
			fmt.Fprintf(&b, "r%d:%s\x00%d:%s\x00%d:%s\x00", len(r.Kind), r.Kind, len(r.Prefix), r.Prefix, len(r.Regex), r.Regex)
		}
	}
	// which categories are on, as covers says: the user's choice
	// (o.Kinds) or a category's default
	for _, c := range Categories {
		fmt.Fprintf(&b, "%s=%t,", c.ID, o.covers(c.ID))
	}
	b.WriteByte(0)
	b.WriteString(dateClock().Format("2006-01-02"))
	return b.String()
}

// memoRuleSpans is ruleSpans, remembered for a long s.
func memoRuleSpans(s string, o Options) []span {
	if len(s) < ruleMemoMin || ruleMemoOff.Load() {
		return ruleSpans(s, o)
	}
	print := o.rulesKey
	if print == "" {
		print = rulesPrint(o)
	}
	h := sha256.New()
	h.Write([]byte(print))
	h.Write([]byte{0})
	h.Write([]byte(s))
	var k [32]byte
	h.Sum(k[:0])
	rulesMemo.gets.Add(1)
	if sp, ok := rulesMemo.get(k); ok {
		rulesMemo.hits.Add(1)
		// the caller appends to it
		return slices.Clone(sp)
	}
	sp := ruleSpans(s, o)
	rulesMemo.put(k, slices.Clone(sp))
	return sp
}

func (m *ruleMemo) get(k [32]byte) ([]span, bool) {
	m.Lock()
	defer m.Unlock()
	if sp, ok := m.cur[k]; ok {
		return sp, true
	}
	if sp, ok := m.old[k]; ok {
		m.add(k, sp) // still in use: kept past the next turnover
		return sp, true
	}
	return nil, false
}

func (m *ruleMemo) put(k [32]byte, sp []span) {
	m.Lock()
	defer m.Unlock()
	m.add(k, sp)
}

// add is called with m held.
func (m *ruleMemo) add(k [32]byte, sp []span) {
	size := spanSize * (len(sp) + 1)
	if m.cur == nil || len(m.cur) >= ruleMemoEntries || m.bytes+size > ruleMemoBytes {
		m.old, m.cur, m.bytes = m.cur, make(map[[32]byte][]span), 0
	}
	if old, ok := m.cur[k]; ok {
		m.bytes -= spanSize * (len(old) + 1)
	}
	m.bytes += size
	m.cur[k] = sp
}

// reset forgets everything (a test starts from nothing).
func (m *ruleMemo) reset() {
	m.Lock()
	defer m.Unlock()
	m.cur, m.old, m.bytes = nil, nil, 0
	m.gets.Store(0)
	m.hits.Store(0)
}

// RuleMemoStats is how often the rules' memory was asked and how often it
// had the answer, since magpie started; and what it holds.
func RuleMemoStats() (gets, hits uint64, entries, bytes int) {
	rulesMemo.Lock()
	defer rulesMemo.Unlock()
	return rulesMemo.gets.Load(), rulesMemo.hits.Load(), len(rulesMemo.cur) + len(rulesMemo.old), rulesMemo.bytes
}
