package gateway

import (
	"net/http"
	"strings"
	"testing"

	"github.com/yetone/magpie/internal/provider"
)

// A group whose first member's safety filter refuses the turn and whose
// last is out of its allowance, as on a Kiro group where six accounts
// refused and the seventh answered 429 MONTHLY_REQUEST_COUNT (#4031): the
// agent is told it was refused, a 400, not handed the last member's
// allowance error it takes for the provider being out of quota.
func TestRefusalEarlierWinsOverTheLastAllowance(t *testing.T) {
	for _, x := range []struct {
		name string
		last reply
		fail string
	}{
		{"quota 429", reply{http.StatusTooManyRequests, "", `{"type":"error","error":{"type":"rate_limit_error","message":"usage limit reached: You have reached the limit. (MONTHLY_REQUEST_COUNT)"}}`}, failQuota},
		{"credit 403", reply{http.StatusForbidden, "", `{"error":{"message":"Student plan credits consumed."}}`}, failCredit},
	} {
		t.Run(x.name, func(t *testing.T) {
			fresh(t)
			a := &scripted{replies: []reply{{200, "text/event-stream", chatFiltered}}}
			b := &scripted{replies: []reply{x.last}}
			scriptedOn(t, "a", provider.Chat, a)
			scriptedOn(t, "b", provider.Chat, b)
			refusalGroup(t, "a/m", "b/m")
			s := New()
			code, body := sendTo(s, "/v1/chat/completions", `{"model":"group/g","stream":true,"messages":[{"role":"user","content":"hi"}]}`)
			if code != refusedStatus || !strings.Contains(body, "content_filter") || strings.Contains(body, "MONTHLY_REQUEST_COUNT") || strings.Contains(body, "credits consumed") {
				t.Fatalf("%d %s (a %d, b %d)", code, body, a.n, b.n)
			}
			r := lastRoute(s)
			n := len(r.Tries)
			if n < 2 || r.Tries[0].Fail != failRefused || r.Tries[n-1].ID != "b" || r.Tries[n-1].Fail != x.fail || !r.Tries[n-1].Earlier || r.Status != refusedStatus {
				t.Fatalf("tries: %+v (status %d)", r.Tries, r.Status)
			}
		})
	}
}
