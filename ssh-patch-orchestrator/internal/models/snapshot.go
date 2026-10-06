package models

import "time"

// SnapshotStatus represents the lifecycle status of an LVM snapshot.
type SnapshotStatus string

const (
	SnapshotActive  SnapshotStatus = "ACTIVE"
	SnapshotInvalid SnapshotStatus = "INVALID"
	SnapshotMerged  SnapshotStatus = "MERGED"
	SnapshotRemoved SnapshotStatus = "REMOVED"
)

// Snapshot records the identity and state of an LVM snapshot bound to a job.
type Snapshot struct {
	SnapshotID     string         `json:"snapshot_id"`
	JobID          string         `json:"job_id"`
	VG             string         `json:"vg"`
	OriginLV       string         `json:"origin_lv"`
	SnapshotLV     string         `json:"snapshot_lv"`
	LVUUID         string         `json:"lv_uuid"`
	Size           string         `json:"size"`
	CreatedAt      time.Time      `json:"created_at"`
	Verified       bool           `json:"verified"`
	COWUsagePercent float64       `json:"cow_usage_percent"`
	Status         SnapshotStatus `json:"status"`
}
