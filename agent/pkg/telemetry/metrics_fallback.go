//go:build !windows

package telemetry

func queryWindowsMemoryLoad() float64 {
	return 35.0
}

func queryWindowsSystemTimes() (idle, total uint64, ok bool) {
	return 0, 0, false
}
