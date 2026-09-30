package scope_test

import (
	"reflect"
	"testing"

	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/scope"
)

// TD-SCOPE-1. 스코프 게이트·라우팅.
func TestScopeGate(t *testing.T) {
	m := scope.NewMaster([]string{"node-a", "node-b"})

	t.Run("an unregistered node is filtered out of collection", func(t *testing.T) {
		allowed, rejected := m.Gate([]string{"node-a", "node-x", "node-b"})
		if !reflect.DeepEqual(allowed, []string{"node-a", "node-b"}) {
			t.Errorf("allowed = %v, want [node-a node-b]", allowed)
		}
		if !reflect.DeepEqual(rejected, []string{"node-x"}) {
			t.Errorf("rejected = %v, want [node-x]", rejected)
		}
	})

	t.Run("an unregistered observed node → registration decision requested (not collected)", func(t *testing.T) {
		if got := m.ClassifyObserved("node-x"); got != scope.RegistrationRequest {
			t.Errorf("ClassifyObserved(unregistered) = %v, want RegistrationRequest", got)
		}
		if got := m.ClassifyObserved("node-a"); got != scope.InScope {
			t.Errorf("ClassifyObserved(registered) = %v, want InScope", got)
		}
	})
}
