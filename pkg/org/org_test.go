package org_test

import (
	"errors"
	"testing"

	"github.com/randyinthedev-hash/pqcota-common/pkg/org"
)

// TestParseRejectsWhatCannotBeToldApart — 사람이 같게 읽고 기계가 다르게 읽는 이름을 받지 않는다.
func TestParseRejectsWhatCannotBeToldApart(t *testing.T) {
	for _, s := range []string{"", " ", "a", "Acme", "ACME", "-acme", "acme_corp", "acme.corp", "acme corp"} {
		if got, err := org.Parse(s); err == nil {
			t.Errorf("%q was accepted → %q", s, got)
		}
	}
	for _, s := range []string{"ac", "acme", "acme-corp", "org-2026", "a1"} {
		if _, err := org.Parse(s); err != nil {
			t.Errorf("%q was rejected: %v", s, err)
		}
	}
}

// TestEmptyIsNotAChoice — 빈 조직은 Default를 고른 것이 아니라 대다 만 것이다.
func TestEmptyIsNotAChoice(t *testing.T) {
	if _, err := org.Parse(""); !errors.Is(err, org.ErrEmpty) {
		t.Fatalf("an empty organization is not ErrEmpty: %v", err)
	}
	if org.Default == "" {
		t.Fatal("Default is empty — \"no organization\" and \"organization not written\" take the same shape")
	}
}

// TestResolveFallsBackButNeverGuesses — 안 적은 것은 기본값으로, 틀리게 적은 것은 에러로.
func TestResolveFallsBackButNeverGuesses(t *testing.T) {
	got, err := org.Resolve("")
	if err != nil || got != org.Default {
		t.Fatalf("empty input does not resolve to Default: %q %v", got, err)
	}
	if _, err := org.Resolve("Acme"); err == nil {
		t.Fatal("a typo was swallowed into the default — where that row went becomes unknowable")
	}
}

// TestRequiredModeRefusesTheDefault — 여럿을 담는 배포에서 조직 없는 호출은 여는 자리에서 터진다.
func TestRequiredModeRefusesTheDefault(t *testing.T) {
	t.Setenv(org.RequireEnv, "1")
	if _, err := org.Resolve(""); !errors.Is(err, org.ErrDefaultNotAllowed) {
		t.Fatalf("in required mode it opened with the default organization: %v", err)
	}
	if got, err := org.Resolve("acme"); err != nil || got != org.ID("acme") {
		t.Fatalf("in required mode a valid organization was blocked: %q %v", got, err)
	}
}

// TestDefaultIsReservedInRequiredMode — `default`는 모양 규칙을 통과하므로 막지 않으면
// 고객 조직 ID로 배정될 수 있다. 배정되는 순간 단일 조직 시절 데이터와 한 조직이 된다.
func TestDefaultIsReservedInRequiredMode(t *testing.T) {
	if _, err := org.Parse(string(org.Default)); err != nil {
		t.Fatal("premise check: Default passes the shape rule — which is why it must be reserved")
	}
	t.Setenv(org.RequireEnv, "1")
	if _, err := org.Resolve(string(org.Default)); !errors.Is(err, org.ErrReserved) {
		t.Fatalf("in required mode a reserved name opened as an organization: %v", err)
	}
}
