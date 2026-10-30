package redact

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// memoTexts are what a conversation's history is on its next turn: the
// same long strings again.
func memoTexts() []string { return gateTexts() }

func memoBody(texts []string) []byte {
	var msgs []string
	for _, t := range texts {
		msgs = append(msgs, fmt.Sprintf(`{"role":"user","content":[{"type":"text","text":%q}]}`, t))
	}
	// a tool call's arguments are masked as JSON text of their own (asJSON)
	msgs = append(msgs, `{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"bash","input":{"command":"x"}}]}`,
		`{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"bash","arguments":"{\"command\":\"curl -H 'x-api-key: `+"sk-"+`proj-AbCdEfGhIjKlMnOpQrStUv12' https://api.example.com \\n# mail rkato`+"@"+`acme-corp.cn\"}"}}]}`)
	return []byte(`{"model":"m","messages":[` + strings.Join(msgs, ",") + `]}`)
}

// fresh masks with nothing remembered: no rules' memory, no values known.
func fresh(f func()) {
	Forget()
	ruleMemoOff.Store(true)
	defer ruleMemoOff.Store(false)
	f()
}

// TestRuleMemoMasksAsWithout: a body masked with the rules' memory, cold
// and warm, is byte for byte what it is without it, for every setting the
// rules read.
func TestRuleMemoMasksAsWithout(t *testing.T) {
	defer Forget()
	body := memoBody(memoTexts())
	opts := []Options{
		{Secrets: true, Personal: true},
		{Secrets: true},
		{Personal: true},
		{Secrets: true, Personal: true, Kinds: map[string]bool{"mac": false, "home": true, "userhost": true}},
		{Secrets: true, Personal: true, Words: []string{"acme-corp", "build"}, WordsWhole: true},
		{Secrets: true, Personal: true, Words: []string{"STEP"}, WordsAnyCase: true},
		{Secrets: true, Rules: []Rule{{Kind: "ticket", Regex: `step \d+\.\d+`}}},
		{Secrets: true, Personal: true, Allow: []string{"rkato" + "@" + "acme-corp.cn"}, Actions: map[string]string{"PHONE": Warn}},
	}
	for i, o := range opts {
		var want []byte
		var wantN int
		fresh(func() { want, wantN = MaskJSON(body, o) })
		Forget()
		for pass := range 3 {
			got, n := MaskJSON(body, o)
			if string(got) != string(want) || n != wantN {
				t.Fatalf("options %d, pass %d: masked with the memory differs from without (%d values, want %d)", i, pass, n, wantN)
			}
		}
	}
}

// TestRuleMemoKeyedBySettings: a span found under one setting is not used
// under another, in either order.
func TestRuleMemoKeyedBySettings(t *testing.T) {
	defer Forget()
	body := memoBody(memoTexts())
	a := Options{Secrets: true, Personal: true}
	b := Options{Secrets: true, Personal: true, Kinds: map[string]bool{"ssn": false, "mac": false}}
	var wantA, wantB []byte
	fresh(func() { wantA, _ = MaskJSON(body, a) })
	fresh(func() { wantB, _ = MaskJSON(body, b) })
	if string(wantA) == string(wantB) {
		t.Fatal("the two settings mask the same: the test tells nothing")
	}
	Forget()
	for range 2 {
		if got, _ := MaskJSON(body, a); string(got) != string(wantA) {
			t.Fatal("a masked as b")
		}
		if got, _ := MaskJSON(body, b); string(got) != string(wantB) {
			t.Fatal("b masked as a")
		}
	}
}

// TestRuleMemoKeyedByDay: a date that was not a birthday yesterday (less
// than a year ago) is one today, remembered or not.
func TestRuleMemoKeyedByDay(t *testing.T) {
	defer Forget()
	defer func(c func() time.Time) { dateClock = c }(dateClock)
	text := strings.Repeat("plain text around it. ", 20) + "born on 2025-10-30, as the form says"
	o := Options{Secrets: true, Personal: true}
	dateClock = func() time.Time { return time.Date(2026, 10, 29, 12, 0, 0, 0, time.Local) }
	Forget()
	if got, _ := Mask(text, o); strings.Contains(got, "{{BIRTHDAY_") {
		t.Fatal("a date under a year ago masked as a birthday")
	}
	dateClock = func() time.Time { return time.Date(2026, 10, 31, 12, 0, 0, 0, time.Local) }
	if got, _ := Mask(text, o); !strings.Contains(got, "{{BIRTHDAY_") {
		t.Fatal("the next day's mask used the day before's spans")
	}
}

// TestRuleMemoValueLetGo: a value remembered by the rules' spans but let
// go from values since (makeRoom) is masked again with its placeholder,
// and put back: the memory holds places, not placeholders.
func TestRuleMemoValueLetGo(t *testing.T) {
	defer Forget()
	text := strings.Repeat("plain text around it. ", 20) + "DB_PASSWORD=" + "Tr0ub4dor" + "Zx81q"
	o := Options{Secrets: true}
	Forget()
	first, _ := Mask(text, o)
	mu.Lock()
	values = map[string]string{}
	reindexKnown()
	mu.Unlock()
	again, _ := Mask(text, o)
	if again != first {
		t.Fatalf("masked again as %q, first %q", again, first)
	}
	if Restore(again, false) != text {
		t.Fatal("the placeholder made from remembered spans isn't put back")
	}
}

// TestRuleMemoHits: the history of the turn before is read by the rules
// once, the new turn's text alone the next time.
func TestRuleMemoHits(t *testing.T) {
	defer Forget()
	texts := memoTexts()
	o := Options{Secrets: true, Personal: true}
	Forget()
	MaskJSON(memoBody(texts[:20]), o)
	g0, h0, _, _ := RuleMemoStats()
	MaskJSON(memoBody(texts[:21]), o)
	g1, h1, _, _ := RuleMemoStats()
	if miss := (g1 - g0) - (h1 - h0); miss != 1 {
		t.Fatalf("the next turn read %d long strings anew, want 1 (the new one)", miss)
	}
}

// TestRuleMemoBounded: the memory turns over at its bounds and holds at
// most two generations.
func TestRuleMemoBounded(t *testing.T) {
	defer Forget()
	Forget()
	o := Options{Secrets: true, Personal: true}
	base := strings.Repeat("x", ruleMemoMin)
	for i := range 3 * ruleMemoEntries {
		memoRuleSpans(fmt.Sprintf("%s %d", base, i), o)
	}
	_, _, entries, bytes := RuleMemoStats()
	if entries > 2*ruleMemoEntries || bytes > ruleMemoBytes {
		t.Fatalf("holds %d entries, %d bytes", entries, bytes)
	}
}

// TestRuleMemoConcurrent: requests masked at once (run with -race) each
// come out as masked alone.
func TestRuleMemoConcurrent(t *testing.T) {
	defer Forget()
	texts := memoTexts()
	o := Options{Secrets: true, Personal: true}
	var want [][]byte
	fresh(func() {
		for i := range 8 {
			out, _ := MaskJSON(memoBody(texts[i:i+12]), o)
			want = append(want, out)
		}
	})
	Forget()
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range 8 {
				i := (w + r) % 8
				if got, _ := MaskJSON(memoBody(texts[i:i+12]), o); string(got) != string(want[i]) {
					errs <- fmt.Sprintf("worker %d, body %d differs", w, i)
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// conversation is an agent's request on each of turns turns: the history so
// far and one new turn, its messages a few KB each, as tool output is. The
// text is magpie's own source (this package), so the rules read code, with
// a value for them every few messages.
func conversation(tb testing.TB, turns int) [][]byte {
	tb.Helper()
	var src strings.Builder
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue // no values the tests make
		}
		b, err := os.ReadFile(f)
		if err != nil {
			tb.Fatal(err)
		}
		src.Write(b)
	}
	code := src.String()
	values := memoTexts()
	var msgs []string
	var out [][]byte
	at := 0
	for turn := range turns {
		for j := range 6 {
			n := 1500 + (turn*7+j*13)%6500
			if at+n > len(code) {
				at = 0
			}
			text := code[at : at+n]
			at += n
			if j == 0 {
				text = values[turn%len(values)][:400] + text
			}
			role := "user"
			if j%2 == 1 {
				role = "assistant"
			}
			m, _ := json.Marshal(map[string]any{"role": role, "content": []map[string]string{{"type": "text", "text": text}}})
			msgs = append(msgs, string(m))
		}
		out = append(out, []byte(`{"model":"m","max_tokens":8192,"messages":[`+strings.Join(msgs, ",")+`]}`))
	}
	return out
}

// BenchmarkMaskJSONTurn masks a 60-turn conversation turn by turn, as the
// gateway sees it, with the rules' memory and the gate on (memo), and off
// (rules). ns/op is a whole conversation.
func BenchmarkMaskJSONTurn(b *testing.B) {
	turns := conversation(b, 60)
	var size int64
	for _, t := range turns {
		size += int64(len(t))
	}
	o := Options{Secrets: true, Personal: true}
	for _, mode := range []struct {
		name string
		off  bool
	}{{"memo", false}, {"rules", true}} {
		b.Run(mode.name, func(b *testing.B) {
			ruleMemoOff.Store(mode.off)
			ruleGateOff.Store(mode.off)
			defer ruleMemoOff.Store(false)
			defer ruleGateOff.Store(false)
			b.SetBytes(size)
			for range b.N {
				Forget()
				for _, t := range turns {
					MaskJSON(t, o)
				}
			}
		})
	}
	Forget()
}

// TestRuleMemoConversation: every turn of a conversation is masked with
// the memory as it is without it.
func TestRuleMemoConversation(t *testing.T) {
	defer Forget()
	turns := conversation(t, 30)
	o := Options{Secrets: true, Personal: true}
	var want [][]byte
	fresh(func() {
		for _, b := range turns {
			out, _ := MaskJSON(b, o)
			want = append(want, out)
		}
	})
	Forget()
	for i, b := range turns {
		if got, _ := MaskJSON(b, o); string(got) != string(want[i]) {
			t.Fatalf("turn %d masked otherwise with the memory", i)
		}
	}
}
