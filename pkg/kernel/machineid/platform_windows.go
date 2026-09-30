//go:build windows

package machineid

import (
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// MachineGuidPath — Windows의 설치 단위 안정 식별자가 사는 곳. `/etc/machine-id`의 대응물이다.
// OS를 다시 깔면 바뀌고, 호스트명을 바꿔도 그대로다 — 노드 이력이 이름에 흔들리지 않게 하는 앵커.
const MachineGuidPath = `SOFTWARE\Microsoft\Cryptography`

// platformIDs — Windows 경로의 안정 지문.
//
// `certutil`·WMI·PowerShell을 부르지 않고 레지스트리와 펌웨어 테이블을 직접 읽는다(§2.3,
// collector와 같은 원칙). 둘의 성질이 다르다: MachineGuid는 **설치** 단위(다시 깔면 바뀐다),
// SMBIOS UUID는 **하드웨어** 단위(OS를 갈아도 그대로다). 그래서 둘 다 모은다.
func platformIDs() (machineID, hardwareUUID string) {
	return machineGUID(), smbiosUUID()
}

func machineGUID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, MachineGuidPath, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	guid, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return ""
	}
	return guid
}

var (
	kernel32                   = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemFirmwareTable = kernel32.NewProc("GetSystemFirmwareTable")
)

// smbiosUUID — SMBIOS Type 1(System Information)의 UUID. 못 읽으면 빈 값이다(§2.5 — 지어내지 않는다).
//
// 리눅스의 `/sys/class/dmi/id/product_uuid`와 **같은 값**이 나와야 한다: 한 머신이 듀얼 부팅이든
// 이미지 이관이든 같은 하드웨어로 상관돼야 하기 때문이다. SMBIOS 2.6+는 앞 세 묶음을 리틀엔디언으로
// 담으므로 그 순서를 되돌려 적는다 — dmidecode·sysfs가 쓰는 표기와 맞춘다.
func smbiosUUID() string {
	const rsmb = 0x52534D42 // 'RSMB'
	size, _, _ := procGetSystemFirmwareTable.Call(uintptr(rsmb), 0, 0, 0)
	if size == 0 {
		return ""
	}
	buf := make([]byte, size)
	n, _, _ := procGetSystemFirmwareTable.Call(uintptr(rsmb), 0, uintptr(unsafe.Pointer(&buf[0])), size)
	if n == 0 || n > size {
		return ""
	}
	return parseSMBIOSUUID(buf[:n])
}
