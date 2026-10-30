package gateway

import (
	"strings"
	"testing"
	"time"

	"github.com/yetone/magpie/internal/provider"
)

// A member resting until the window it filled renews isn't the request's
// probe: a Kiro account at 100% of its month, resting "by window" until
// the month's reset, was asked last by every request whose other members
// refused, 3 s for a 429 each time. Members not resting are asked as
// ever, and a member resting for a guessed while still is.
func TestProbeLeavesOutARestWhoseEndIsNamed(t *testing.T) {
	fresh(t)
	h := &hits{n: map[string]int{}}
	for _, id := range []string{"a", "b", "c"} {
		serveOn(t, id, "k-"+id, []string{"m"}, h.on(id))
	}
	if err := provider.SaveGroup(provider.Group{Name: "Spent", Members: []string{"a/m", "b/m", "c/m"}, Routing: provider.Ordered}); err != nil {
		t.Fatal(err)
	}
	s := New()
	now := time.Now()
	restBy(t, s, "spent", map[string]Rest{"b": {Why: failQuota, Status: 429, By: "window", Until: now.Add(48 * time.Hour)}})
	if code, body := postAs(t, s, "", `{"model":"group/spent","messages":[{"role":"user","content":"hi"}]}`); code < 400 {
		t.Fatalf("every member fails, answered %d %s", code, body)
	}
	if got := h.got(); got["a"] != 1 || got["c"] != 1 || got["b"] != 0 {
		t.Fatalf("asked %v, want a and c, not b", got)
	}
	r := s.trace.routes[len(s.trace.routes)-1]
	if len(r.Order) != 3 {
		t.Fatalf("the trace leaves out a member: %+v", r.Order)
	}

	// with nobody else, the one back soonest is asked
	restBy(t, s, "spent", map[string]Rest{
		"a": {Why: failQuota, Status: 429, By: "resets", Until: now.Add(9 * time.Hour)},
		"b": {Why: failQuota, Status: 429, By: "window", Until: now.Add(48 * time.Hour)},
		"c": {Why: failQuota, Status: 429, By: "window", Until: now.Add(3 * time.Hour)},
	})
	h.n = map[string]int{}
	if code, body := postAs(t, s, "", `{"model":"group/spent","messages":[{"role":"user","content":"hi"}]}`); code < 400 {
		t.Fatalf("every member fails, answered %d %s", code, body)
	}
	if got := h.got(); got["a"] != 0 || got["b"] != 0 || got["c"] != 1 {
		t.Fatalf("asked %v, want c alone", got)
	}
}

// probeOne leaves out every rest whose end is named, keeps a guessed one
// as the probe beside them, and with only named rests keeps the soonest.
func TestProbeOneNamedRests(t *testing.T) {
	fresh(t)
	c := func(id string) candidate { return candidate{p: provider.Provider{ID: id}, model: "m", rest: id} }
	cs := []candidate{c("a"), c("b"), c("c"), c("d")}
	ids := func(cs []candidate) string {
		var out []string
		for _, c := range cs {
			out = append(out, c.p.ID)
		}
		return strings.Join(out, " ")
	}
	now := time.Now()
	rest := func(id, by string, d time.Duration) {
		restingUntil.Lock()
		defer restingUntil.Unlock()
		restingUntil.m[id] = now.Add(d)
		restingUntil.note[id] = Rest{Why: failQuota, By: by, Key: id}
	}
	rest("b", "window", time.Minute)
	if got := ids(probeOne(cs)); got != "a c d" {
		t.Fatalf("one resting by window: %s", got)
	}
	rest("c", "quota", 9*time.Minute)
	if got := ids(probeOne(cs)); got != "a c d" {
		t.Fatalf("and one guessed: %s", got)
	}
	rest("a", "resets", 5*time.Minute)
	rest("d", "retry-after", 2*time.Minute)
	if got := ids(probeOne(cs)); got != "d" {
		t.Fatalf("two named, two guessed: %s", got)
	}
	if got := ids(probeOne([]candidate{c("a"), c("b")})); got != "b" {
		t.Fatalf("only named rests: %s", got)
	}
}

// restBy rests each named member of group's candidates as given.
func restBy(t *testing.T, s *Server, group string, rests map[string]Rest) {
	t.Helper()
	g, ms, ok := provider.FindGroup("group/" + group)
	if !ok {
		t.Fatalf("no group %s", group)
	}
	cs, _ := s.planGroup(g.Live(), ms, provider.Chat)
	restingUntil.Lock()
	defer restingUntil.Unlock()
	for _, c := range cs {
		if r, ok := rests[c.p.ID]; ok {
			restingUntil.m[c.restKey()] = r.Until
			r.Key = c.restKey()
			restingUntil.note[c.restKey()] = r
		}
	}
}
