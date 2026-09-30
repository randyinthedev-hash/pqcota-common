// Package machineid — 머신 상관 지문 수집 + 자동 UID(self-id) 결정론적 부여 (규정서 §1.4).
// 권위 머신 ID는 CMDB(스코프 마스터). CMDB가 없으면 안정 지문에서 **결정론적으로** self-id를 파생한다
// — 랜덤이 아니라 같은 머신이면 항상 같은 값이라 중복이 없다. IP는 ID가 아니라 로케이터.
package machineid

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
)

// SelfAssign — 지문에서 결정론적 node_id를 파생한다(§1.4 self-id). CMDB 미등재 폴백.
// 우선순위(안정성 순): cloud-instance-id > machine-id > hardware-uuid > fqdn.
// 반환: ("node:"+sha256(종류=값)[:16], 사용한 지문 종류). 지문이 하나도 없으면 ("","").
func SelfAssign(fp *commonv1.MachineIdentity) (id, derivedFrom string) {
	var src, val string
	switch {
	case fp.GetCloudInstanceId() != "":
		src, val = "cloud-instance-id", fp.GetCloudInstanceId()
	case fp.GetMachineId() != "":
		src, val = "machine-id", fp.GetMachineId()
	case fp.GetHardwareUuid() != "":
		src, val = "hardware-uuid", fp.GetHardwareUuid()
	case fp.GetFqdn() != "":
		src, val = "fqdn", fp.GetFqdn()
	default:
		return "", "" // 지문 없음 — self-id 불가(정직히 빈 값)
	}
	sum := sha256.Sum256([]byte(src + "=" + val))
	return "node:" + hex.EncodeToString(sum[:])[:16], src
}

// Fingerprint — 호스트에서 안정 지문을 best-effort 수집한다. 없는 건 빈 값으로 남긴다(§2.5 정직).
// self_assigned_id/derived_from도 함께 채운다.
//
// 지문의 **출처는 OS마다 다르다**(리눅스는 /etc/machine-id·DMI, Windows는 레지스트리) — 그 부분만
// [platformIDs]로 갈라 두고 나머지 규칙은 한 곳에 둔다. 갈라 두지 않았을 때 Windows 노드가
// 표시 없이 fqdn으로 떨어졌다(TD-CNG-7): 호스트명을 바꾸면 같은 머신이 다른 노드가 된다.
func Fingerprint() *commonv1.MachineIdentity {
	machineID, hardwareUUID := platformIDs()
	fp := &commonv1.MachineIdentity{
		MachineId:       machineID,
		HardwareUuid:    hardwareUUID,
		CloudInstanceId: strings.TrimSpace(os.Getenv("PQCOTA_CLOUD_INSTANCE_ID")),
	}
	if h, err := os.Hostname(); err == nil {
		fp.Fqdn = h
	}
	fp.SelfAssignedId, fp.DerivedFrom = SelfAssign(fp)
	return fp
}

func firstLine(paths ...string) string {
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				return s
			}
		}
	}
	return ""
}
