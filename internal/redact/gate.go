package redact

import "sync/atomic"

// ruleGateOff runs every rule with no marker over every text, as before
// textShape; for the tests too.
var ruleGateOff atomic.Bool

// textShape is what one pass over a text says it can hold, for the rules
// with no marker (rule.digitRun, rule.anyOf).
type textShape struct {
	digitRun int
	has      [256]bool
}

func shapeOfText(s string) *textShape {
	t := &textShape{}
	run := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			run++
			if run > t.digitRun {
				t.digitRun = run
			}
			continue
		}
		run = 0
		t.has[c] = true
	}
	return t
}

// hasAny says the text has one of the bytes of set.
func (t *textShape) hasAny(set string) bool {
	for i := 0; i < len(set); i++ {
		if t.has[set[i]] {
			return true
		}
	}
	return false
}
