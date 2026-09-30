package completeness_test

import (
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/completeness"
)

// TD-GAP-1. 완전성 맵 — 갭 ≠ 부재.
func TestCompleteness(t *testing.T) {
	proc := commonv1.CollectionLayer_COLLECTION_LAYER_PROCESS
	arti := commonv1.CollectionLayer_COLLECTION_LAYER_ARTIFACT

	t.Run("PROCESS declared but not covered → a gap is recorded", func(t *testing.T) {
		c := completeness.BuildCompleteness(
			[]commonv1.CollectionLayer{proc, arti}, // 커버 가능하다고 선언
			[]commonv1.CollectionLayer{arti},       // 실제로는 artifact만 (프로세스 미실행)
			"process layer not collected — the target was not running",
		)
		if len(c.LayersMissing) != 1 || c.LayersMissing[0] != proc {
			t.Fatalf("layers_missing = %v, want [PROCESS]", c.LayersMissing)
		}
		if c.Note == "" {
			t.Error("the gap note must not be empty — no automatic 'absent' (§2.5)")
		}
	})

	t.Run("everything covered → no gap", func(t *testing.T) {
		c := completeness.BuildCompleteness(
			[]commonv1.CollectionLayer{proc, arti},
			[]commonv1.CollectionLayer{arti, proc},
			"",
		)
		if len(c.LayersMissing) != 0 {
			t.Fatalf("layers_missing = %v, want empty", c.LayersMissing)
		}
	})
}
