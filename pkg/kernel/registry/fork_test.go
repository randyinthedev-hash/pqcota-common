package registry_test

import (
	"testing"

	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/registry"
)

// TD-FORK-1 (testcases.md §2). fork 시그니처 매처.
func TestMatchFork(t *testing.T) {
	sigs := registry.DefaultForkSignatures
	t.Run("stripped BoringSSL binary", func(t *testing.T) {
		got := registry.MatchFork([]string{"random", "built with BoringSSL", "abc"}, sigs)
		if !got.Matched || got.Fork != "BoringSSL" {
			t.Fatalf("got %+v, want fork=BoringSSL matched", got)
		}
	})
	t.Run("no signature → explicitly unknown", func(t *testing.T) {
		got := registry.MatchFork([]string{"no", "crypto", "markers"}, sigs)
		if got.Matched || got.Fork != "" {
			t.Fatalf("got %+v, want fork=\"\" not matched (unknown)", got)
		}
	})
	t.Run("AWS-LC with the same soname is told apart (never misread as OpenSSL)", func(t *testing.T) {
		// AWS-LC 바이너리는 "OpenSSL" 호환 문자열도 포함할 수 있다.
		got := registry.MatchFork([]string{"OpenSSL 1.1.1 compatible", "AWS-LC 1.2.0"}, sigs)
		if !got.Matched || got.Fork != "AWS-LC" {
			t.Fatalf("got %+v, want fork=AWS-LC (not OpenSSL)", got)
		}
	})
	t.Run("OpenSSL version extraction", func(t *testing.T) {
		got := registry.MatchFork([]string{"OpenSSL 3.0.2 15 Mar 2022"}, sigs)
		if got.Fork != "OpenSSL" || got.Version != "3.0.2" {
			t.Fatalf("got %+v, want fork=OpenSSL version=3.0.2", got)
		}
	})
	t.Run("the version comes from the banner string (even when a name-only string comes first)", func(t *testing.T) {
		// 실제 libcrypto: "OpenSSLDIR" 등 이름만 있는 문자열이 배너보다 먼저 나올 수 있다.
		got := registry.MatchFork([]string{"OpenSSLDIR: \"/usr/lib/ssl\"", "OpenSSL 3.0.11 19 Sep 2023"}, sigs)
		if got.Fork != "OpenSSL" || got.Version != "3.0.11" {
			t.Fatalf("got %+v, want fork=OpenSSL version=3.0.11", got)
		}
	})
}
