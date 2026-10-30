package redact

import (
	"fmt"
	"strings"
	"testing"
)

// gateTexts are long strings with something for most rules.
func gateTexts() []string {
	// each value is put together here, so no rule finds it in this file
	at := "@"
	parts := []string{
		"DB_PASSWORD=" + "Tr0ub4dor" + "Zx81q\nAPI_KEY: \"" + "sk-" + "proj-AbCdEfGhIjKlMnOpQrStUv12" + "\"\n",
		"write to rkato" + at + "acme-corp.cn or call 138" + "0013" + "8000 today\n",
		"card 4111 1111 " + "1111 1111 and id " + idCard("11010119900307001") + "\n",
		"postgres://app:" + "s3cretPw" + "Q7" + at + "db.acme-corp.cn:5432/main\n",
		"MAC 00:1A:2B" + ":3C:4D:5E SSN 123-45-" + "6789 IBAN GB82" + "WEST12345698765432\n",
		"serial: C02XK" + "1JHG8WP, born on " + "1990-03-07, 密码：" + "abc" + "12345\n",
		"ssh rkato" + at + "box17 ~ and /Users/" + "rkato/src\n",
		"nothing to see here but code: for i := 0; i < n; i++ { x += i }\n",
	}
	var out []string
	for i := range 24 {
		var b strings.Builder
		for j := range 12 {
			b.WriteString(parts[(i+j)%len(parts)])
			fmt.Fprintf(&b, "step %d.%d of the build log, all of it plain text to read through\n", i, j)
		}
		out = append(out, b.String())
	}
	return out
}

// TestRuleGateFindsAsWithout: the rules with no marker skipped by a text's
// shape find nothing in the texts they skip, on texts made to sit at the
// gate's edges.
func TestRuleGateFindsAsWithout(t *testing.T) {
	defer Forget()
	texts := append(gateTexts(),
		"1380013800 is ten digits", "138"+"00138000", "+86 138"+"00138000", "4111111111"+"111111", "4111-1111-"+"1111-1111",
		"GB82WEST"+"12345698765432", "GB82 WEST 1234 "+"5698 7654 32", "00:1A:2B:"+"3C:4D:5E", "00-1A-2B-"+"3C-4D-5E",
		idCard("11010119900307001"), "123-45-"+"6789", "a.b.c 1.2.3", "１３８００１３８０００",
	)
	o := Options{Secrets: true, Personal: true, Kinds: map[string]bool{"ip": true, "home": true, "userhost": true, "bucket": true}}
	for _, s := range texts {
		ruleGateOff.Store(true)
		Forget()
		want, _ := Mask(s, o)
		ruleGateOff.Store(false)
		Forget()
		got, _ := Mask(s, o)
		if got != want {
			t.Errorf("%q: gated %q, ungated %q", s, got, want)
		}
	}
}

// idCard is a Chinese ID number of 17 digits with its check digit.
func idCard(d17 string) string {
	w := []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	sum := 0
	for i, c := range d17 {
		sum += int(c-'0') * w[i]
	}
	return d17 + string("10X98765432"[sum%11])
}
