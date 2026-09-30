package machineid

import (
	"encoding/hex"
	"strings"
)

// parseSMBIOSUUID — RawSMBIOSData(헤더 8바이트) 뒤의 구조체들에서 Type 1의 UUID를 뽑는다.
// 순수 함수라 Windows 없이 테스트된다 — 바이트를 세는 코드는 눈으로 봐서는 맞는지 알 수 없다.
func parseSMBIOSUUID(raw []byte) string {
	const header = 8 // Used20CallingMethod, Major, Minor, DmiRevision, Length(4)
	if len(raw) <= header {
		return ""
	}
	t := raw[header:]
	for len(t) >= 4 {
		typ, l := t[0], int(t[1])
		if l < 4 || l > len(t) {
			return ""
		}
		if typ == 1 { // System Information — UUID는 오프셋 8부터 16바이트
			if l < 24 {
				return ""
			}
			return formatSMBIOSUUID(t[8:24])
		}
		// 구조체 뒤에는 문자열 영역이 붙고 0x00 0x00으로 끝난다.
		rest := t[l:]
		i := 0
		for i+1 < len(rest) && !(rest[i] == 0 && rest[i+1] == 0) {
			i++
		}
		if i+1 >= len(rest) {
			return ""
		}
		t = rest[i+2:]
	}
	return ""
}

// formatSMBIOSUUID — 16바이트를 dmidecode·sysfs와 같은 표기로. 앞 세 묶음은 리틀엔디언이다.
func formatSMBIOSUUID(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	all0, allF := true, true
	for _, c := range b {
		if c != 0x00 {
			all0 = false
		}
		if c != 0xFF {
			allF = false
		}
	}
	if all0 || allF {
		return "" // 펌웨어가 값을 안 채운 것이다 — 0으로 채워진 UUID를 식별자로 쓰지 않는다
	}
	h := func(bs ...byte) string { return hex.EncodeToString(bs) }
	return strings.ToUpper(strings.Join([]string{
		h(b[3], b[2], b[1], b[0]),
		h(b[5], b[4]),
		h(b[7], b[6]),
		h(b[8], b[9]),
		h(b[10], b[11], b[12], b[13], b[14], b[15]),
	}, "-"))
}
