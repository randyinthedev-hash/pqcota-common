package machineid

import "testing"

// TK-MACHINE-SMBIOS — SMBIOS Type 1의 UUID를 리눅스 sysfs와 **같은 표기**로 뽑는다.
//
// 한 머신이 듀얼 부팅이든 이미지 이관이든 같은 하드웨어로 상관돼야 하는데, 앞 세 묶음이
// 리틀엔디언이라 그 순서를 되돌리지 않으면 같은 머신이 다른 UUID로 보인다. 바이트를 세는
// 코드는 눈으로 봐서는 맞는지 알 수 없어 여기서 못 박는다.
func TestParseSMBIOSUUID(t *testing.T) {
	// RawSMBIOSData 헤더 8바이트 + Type 1 구조체(길이 27) + 문자열 영역 종료(0x00 0x00).
	raw := append([]byte{0x00, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00},
		1, 27, 0x01, 0x00, // type=1, length=27, handle
		0x01, 0x02, 0x03, 0x04, // manufacturer·product·version·serial (문자열 인덱스)
	)
	uuid := []byte{
		0x78, 0x56, 0x34, 0x12, // 앞 세 묶음은 리틀엔디언으로 담긴다
		0xBC, 0x9A,
		0xF0, 0xDE,
		0x12, 0x34, // 여기부터는 그대로
		0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
	}
	raw = append(raw, uuid...)
	raw = append(raw, 0x00, 0x00, 0x00) // wake-up type + 문자열 영역 종료

	const want = "12345678-9ABC-DEF0-1234-56789ABCDEF0"
	if got := parseSMBIOSUUID(raw); got != want {
		t.Errorf("UUID = %q, want %q — without undoing the little-endian order the same machine looks different", got, want)
	}
}

// 펌웨어가 값을 안 채우면 **빈 값**이다. 0으로 채워진 UUID를 식별자로 쓰면 서로 다른 머신이
// 한 노드로 합쳐진다 — 못 읽은 것을 지어내지 않는다(§2.5).
func TestParseSMBIOSUUIDRefusesPlaceholders(t *testing.T) {
	for name, fill := range map[string]byte{"all 0x00": 0x00, "all 0xFF": 0xFF} {
		b := make([]byte, 16)
		for i := range b {
			b[i] = fill
		}
		if got := formatSMBIOSUUID(b); got != "" {
			t.Errorf("%s, yet a UUID was emitted: %q", name, got)
		}
	}
	if got := formatSMBIOSUUID([]byte{1, 2, 3}); got != "" {
		t.Errorf("not 16 bytes, yet a UUID was emitted: %q", got)
	}
}

// 깨진 입력에 무한 루프나 패닉으로 답하지 않는다 — 펌웨어 테이블은 우리가 만든 것이 아니다.
func TestParseSMBIOSUUIDSurvivesGarbage(t *testing.T) {
	for _, raw := range [][]byte{
		nil,
		{0x00},
		make([]byte, 8),                      // 헤더뿐
		{0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0}, // Type 1인데 길이가 24보다 짧다
		{0, 0, 0, 0, 0, 0, 0, 0, 9, 6, 0, 0}, // 다른 타입 + 문자열 종료가 없다
	} {
		if got := parseSMBIOSUUID(raw); got != "" {
			t.Errorf("a UUID was emitted from broken input: %q (raw=%v)", got, raw)
		}
	}
}
