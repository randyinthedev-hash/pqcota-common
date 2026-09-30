package sign_test

import (
	"testing"
	"time"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/sign"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// 서명이 실제로 무엇을 덮는지 고정한다. 덮이지 않는 필드는 **변조해도 검증이 통과**하므로,
// "서명했다"는 말이 실제보다 강하게 들리게 된다. 각 필드를 흔들어 검증이 깨지는지 본다.

func signed(t *testing.T) (pub string, res *discoveryv1.CollectionResult) {
	t.Helper()
	pub, priv, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	ts := timestamppb.New(time.Unix(1700000000, 0).UTC())
	res = &discoveryv1.CollectionResult{
		Envelope: &commonv1.Envelope{
			CollectorId: "openssl-collector", CollectorVersion: "0.1.0",
			DetectionMethod: commonv1.DetectionMethod_DETECTION_METHOD_RUNTIME_INTROSPECTION,
			CollectedAt:     ts, TargetNodeId: "node-a", ScopeMasterRef: "cmdb-42",
			CollectorLicense: "Apache-2.0",
			Machine: &commonv1.MachineIdentity{
				MachineId: "m-1", HardwareUuid: "hw-1", CloudInstanceId: "i-1",
				Fqdn: "a.example", Ips: []string{"10.0.0.1"},
			},
		},
		RawCapture: []byte("native-output"), RawFormat: "openssl-collector/native-v1",
		CbomCyclonedx: []byte(`{"bomFormat":"CycloneDX"}`), CyclonedxSpecVersion: "1.6",
		Completeness: &commonv1.Completeness{
			LayersCovered: []commonv1.CollectionLayer{commonv1.CollectionLayer_COLLECTION_LAYER_PROCESS},
			LayersMissing: []commonv1.CollectionLayer{commonv1.CollectionLayer_COLLECTION_LAYER_NETWORK},
			Note:          "network layer not collected",
		},
		ObservedEdges: []*discoveryv1.ObservedEdge{{
			SrcNodeId: "node-a", DstNodeId: "node-b", DstAddr: "10.0.0.2:443", Port: 443,
			Protocol:        discoveryv1.NetworkProtocol_NETWORK_PROTOCOL_TLS,
			Role:            discoveryv1.EdgeRole_EDGE_ROLE_CLIENT,
			NegotiatedGroup: "X25519MLKEM768", Cipher: "TLS_AES_128_GCM_SHA256",
			DetectionMethod: commonv1.DetectionMethod_DETECTION_METHOD_RUNTIME_INTROSPECTION,
			ObservedCount:   7, FirstSeen: ts, LastSeen: ts,
		}},
	}
	sig, err := sign.Sign(priv, res)
	if err != nil {
		t.Fatal(err)
	}
	res.Envelope.Signature = sig
	if !sign.Verify([]string{pub}, res) {
		t.Fatal("verification must not fail right after signing")
	}
	return pub, res
}

// 각 필드를 변조하면 검증이 깨져야 한다. 특히 completeness(갭 선언)와 raw_capture(재계산 원본).
func TestTamperBreaksVerification(t *testing.T) {
	cases := map[string]func(*discoveryv1.CollectionResult){
		"envelope.collector_id":      func(r *discoveryv1.CollectionResult) { r.Envelope.CollectorId = "x" },
		"envelope.collector_version": func(r *discoveryv1.CollectionResult) { r.Envelope.CollectorVersion = "9" },
		"envelope.detection_method": func(r *discoveryv1.CollectionResult) {
			r.Envelope.DetectionMethod = commonv1.DetectionMethod_DETECTION_METHOD_SYMBOL_ANALYSIS
		},
		"envelope.collected_at":     func(r *discoveryv1.CollectionResult) { r.Envelope.CollectedAt = timestamppb.Now() },
		"envelope.target_node_id":   func(r *discoveryv1.CollectionResult) { r.Envelope.TargetNodeId = "node-z" },
		"envelope.scope_master_ref": func(r *discoveryv1.CollectionResult) { r.Envelope.ScopeMasterRef = "cmdb-99" },
		"envelope.collector_license": func(r *discoveryv1.CollectionResult) {
			r.Envelope.CollectorLicense = "GPL-3.0-or-later"
		},
		"envelope.machine.machine_id": func(r *discoveryv1.CollectionResult) { r.Envelope.Machine.MachineId = "m-9" },
		"envelope.machine.ips":        func(r *discoveryv1.CollectionResult) { r.Envelope.Machine.Ips = []string{"10.0.0.9"} },
		"raw_capture":                 func(r *discoveryv1.CollectionResult) { r.RawCapture = []byte("swapped") },
		"raw_format":                  func(r *discoveryv1.CollectionResult) { r.RawFormat = "other/v1" },
		"cbom_cyclonedx":              func(r *discoveryv1.CollectionResult) { r.CbomCyclonedx = []byte(`{"bomFormat":"x"}`) },
		"cyclonedx_spec_version":      func(r *discoveryv1.CollectionResult) { r.CyclonedxSpecVersion = "1.7" },
		// ★ 갭 선언 제거 — "원리상 관측하지 못했다"를 "없다"로 바꾸는 변조(§2.6). 반드시 잡혀야 한다.
		"completeness.layers_missing removed": func(r *discoveryv1.CollectionResult) { r.Completeness.LayersMissing = nil },
		"completeness.note":                   func(r *discoveryv1.CollectionResult) { r.Completeness.Note = "" },
		"completeness removed entirely":       func(r *discoveryv1.CollectionResult) { r.Completeness = nil },
		"edge.dst_node_id":                    func(r *discoveryv1.CollectionResult) { r.ObservedEdges[0].DstNodeId = "node-z" },
		"edge.port":                           func(r *discoveryv1.CollectionResult) { r.ObservedEdges[0].Port = 8443 },
		"edge.negotiated_group": func(r *discoveryv1.CollectionResult) {
			r.ObservedEdges[0].NegotiatedGroup = "x25519" // 🟢 → 🔴 등급을 뒤집는 변조
		},
		"edge.cipher":         func(r *discoveryv1.CollectionResult) { r.ObservedEdges[0].Cipher = "NULL" },
		"edge.role":           func(r *discoveryv1.CollectionResult) { r.ObservedEdges[0].Role = discoveryv1.EdgeRole_EDGE_ROLE_SERVER },
		"edge.observed_count": func(r *discoveryv1.CollectionResult) { r.ObservedEdges[0].ObservedCount = 1 },
		"edge.last_seen":      func(r *discoveryv1.CollectionResult) { r.ObservedEdges[0].LastSeen = timestamppb.Now() },
		// 앱을 갈아끼우는 변조 — 어느 앱이 그 통신을 했나가 바뀌면 조치 대상이 바뀐다.
		"edge.app_key":      func(r *discoveryv1.CollectionResult) { r.ObservedEdges[0].AppKey = "other.service" },
		"edge.app_key_kind": func(r *discoveryv1.CollectionResult) { r.ObservedEdges[0].AppKeyKind = "exe-path" },
		"edge added": func(r *discoveryv1.CollectionResult) {
			r.ObservedEdges = append(r.ObservedEdges, &discoveryv1.ObservedEdge{SrcNodeId: "node-a", DstAddr: "10.0.0.3:22"})
		},
		"edge removed": func(r *discoveryv1.CollectionResult) { r.ObservedEdges = nil },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			pub, res := signed(t)
			tamper(res)
			if sign.Verify([]string{pub}, res) {
				t.Errorf("%s was tampered with and verification still passed — this field is a signing blind spot", name)
			}
		})
	}
}

// 엣지 순서가 달라도 같은 관측 집합이면 검증이 통과해야 한다(정렬 정규화).
func TestEdgeOrderDoesNotMatter(t *testing.T) {
	pub, res := signed(t)
	res.ObservedEdges = append(res.ObservedEdges, &discoveryv1.ObservedEdge{
		SrcNodeId: "node-a", DstAddr: "10.0.0.3:22",
		Protocol: discoveryv1.NetworkProtocol_NETWORK_PROTOCOL_SSH,
	})
	// 다시 서명한 뒤 순서만 뒤집는다.
	_, priv, _ := sign.Generate()
	_ = priv
	pub2, priv2, _ := sign.Generate()
	sig, _ := sign.Sign(priv2, res)
	res.Envelope.Signature = sig
	res.ObservedEdges[0], res.ObservedEdges[1] = res.ObservedEdges[1], res.ObservedEdges[0]
	if !sign.Verify([]string{pub2}, res) {
		t.Error("only the edge order changed and verification failed — canonicalization is order-sensitive")
	}
	_ = pub
}

// ★ 필드 수 가드 — 계약에 필드가 늘면 여기서 실패한다. Canonical을 함께 갱신하라는 신호다.
// (서명 사각지대는 표시 없이 생기므로, 실패로 드러나게 만든다.)
func TestCanonicalCoversAllFields(t *testing.T) {
	want := map[string]int{
		"CollectionResult": 7,  // envelope, raw_capture, raw_format, cbom_cyclonedx, spec_version, completeness, observed_edges
		"Envelope":         9,  // 그중 signature는 서명 대상에서 제외(자기 자신)
		"MachineIdentity":  7,  // machine_id, hardware_uuid, cloud_instance_id, fqdn, ips, self_assigned_id, derived_from
		"Completeness":     3,  // layers_covered, layers_missing, note
		"ObservedEdge":     14, // src, dst_node, dst_addr, port, proto, role, group, cipher, detection, count, first, last, app_key, app_key_kind
	}
	got := map[string]int{
		"CollectionResult": (&discoveryv1.CollectionResult{}).ProtoReflect().Descriptor().Fields().Len(),
		"Envelope":         (&commonv1.Envelope{}).ProtoReflect().Descriptor().Fields().Len(),
		"MachineIdentity":  (&commonv1.MachineIdentity{}).ProtoReflect().Descriptor().Fields().Len(),
		"Completeness":     (&commonv1.Completeness{}).ProtoReflect().Descriptor().Fields().Len(),
		"ObservedEdge":     (&discoveryv1.ObservedEdge{}).ProtoReflect().Descriptor().Fields().Len(),
	}
	for msg, n := range want {
		if got[msg] != n {
			t.Errorf("the field count of %s changed from %d to %d.\n"+
				"  when the contract changes, sign.Canonical must change with it — otherwise the new field becomes a signing blind spot.\n"+
				"  once updated, fix this expectation to %d as well and add a case to TestTamperBreaksVerification.\n"+
				"  note: changing the scope of Canonical invalidates every existing signature.", msg, n, got[msg], got[msg])
		}
	}
}
