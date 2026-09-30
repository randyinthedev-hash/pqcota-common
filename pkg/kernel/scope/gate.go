// Package scope — 스코프 마스터 게이트(규정서 §1.4). 자산관리정보(CMDB)가
// 관리 대상 경계의 유일 권위 소스이며, 디스커버리·프로비저닝 대상이 모두 이로 게이트된다.
package scope

// Master — 스코프 마스터(등재 노드 집합). 관리 대상 경계의 유일 권위(§1.4).
type Master struct {
	registered map[string]bool
}

// NewMaster — 등재 노드 ID 집합으로 스코프 마스터를 만든다.
func NewMaster(ids []string) *Master {
	m := &Master{registered: make(map[string]bool, len(ids))}
	for _, id := range ids {
		m.registered[id] = true
	}
	return m
}

// Registered — 노드가 등재되어 있는지.
func (m *Master) Registered(id string) bool { return m.registered[id] }

// Gate — 수집 대상 후보를 등재분(allowed)과 미등재분(rejected)으로 가른다(§1.4).
// 미등재 노드는 원칙적으로 수집 대상이 아니다.
func (m *Master) Gate(targets []string) (allowed, rejected []string) {
	for _, t := range targets {
		if m.registered[t] {
			allowed = append(allowed, t)
		} else {
			rejected = append(rejected, t)
		}
	}
	return allowed, rejected
}

// ObservedDisposition — 수집 중 관측된 노드의 처리(§1.4, SD-5).
type ObservedDisposition int

const (
	// InScope — 등재 노드. 정상 수집 대상.
	InScope ObservedDisposition = iota
	// RegistrationRequest — 미등재 관측 노드. "실행 대상"이 아니라 "등재 판정 요청"으로
	// 라우팅된다(PROPOSE). 임의 수집 금지 — 판정은 사용자(MANUAL).
	RegistrationRequest
)

// ClassifyObserved — 수집 중 관측된 노드를 분류한다. 미등재면 등재 판정 요청으로(§2.5).
func (m *Master) ClassifyObserved(id string) ObservedDisposition {
	if m.registered[id] {
		return InScope
	}
	return RegistrationRequest
}
