// Package completeness — collector가 낸 계층 커버리지(완전성 맵)의 결정론적 조립.
//
// collector는 자기가 본 계층과 볼 수 있다고 선언한 계층만 알리고, 갭(선언−커버)은 여기서 계산한다.
// 단계에 속하지 않고 collector(노드에 나가는 바이너리)와 인벤토리가 함께 쓰므로 kernel에 둔다(규정서 §2.6).
package completeness

import commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"

// MissingLayers — Collector가 커버 가능하다고 선언한(declared) 계층 대비
// 실제 커버한(covered) 계층의 차집합 = 갭 (규정서 §2.6).
//
// 이 갭은 "부재"가 아니다 — 자동 "부재" 처리는 금지된다(§2.5). downstream(Inventory의
// UNOBSERVED 판정, §3.3)이 "실제 없음"과 "원리상 관측하지 못함"을 구분하는 근거가 된다.
func MissingLayers(declared, covered []commonv1.CollectionLayer) []commonv1.CollectionLayer {
	seen := make(map[commonv1.CollectionLayer]bool, len(covered))
	for _, c := range covered {
		seen[c] = true
	}
	var missing []commonv1.CollectionLayer
	for _, d := range declared {
		if !seen[d] {
			missing = append(missing, d)
		}
	}
	return missing
}

// BuildCompleteness — Completeness 메시지를 조립한다. layers_missing은 declared−covered로
// 결정론적으로 계산되며, note는 갭의 사유("대상 미실행" 등)를 사람이 읽을 수 있게 담는다.
func BuildCompleteness(declared, covered []commonv1.CollectionLayer, note string) *commonv1.Completeness {
	return &commonv1.Completeness{
		LayersCovered: covered,
		LayersMissing: MissingLayers(declared, covered),
		Note:          note,
	}
}
