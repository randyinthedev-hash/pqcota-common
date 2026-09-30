//go:build !windows

package machineid

// platformIDs — 리눅스(및 그 밖) 경로의 안정 지문.
//
// `/etc/machine-id`는 설치 단위로 안정하고, DMI product_uuid는 하드웨어/VM 단위다(root 필요).
// 못 읽으면 **빈 값**으로 둔다 — 지어내지 않는다(§2.5).
func platformIDs() (machineID, hardwareUUID string) {
	return firstLine("/etc/machine-id", "/var/lib/dbus/machine-id"),
		firstLine("/sys/class/dmi/id/product_uuid")
}
