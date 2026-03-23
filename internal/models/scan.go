package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type ScanStatus string

const (
	StatusSafe       ScanStatus = "safe"
	StatusSuspicious ScanStatus = "suspicious"
	StatusMalicious  ScanStatus = "malicious"
	StatusUnknown    ScanStatus = "unknown"
	StatusError      ScanStatus = "error"
)

type Scan struct {
	ID     uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	URL    string     `gorm:"type:text;not null;index"                        json:"url"`
	Domain string     `gorm:"type:text;not null;index"                        json:"domain"`
	Status ScanStatus `gorm:"type:text;not null;index;check:status IN ('safe','suspicious','malicious','unknown','error')" json:"status"`

	VirusTotalScore *int    `gorm:"type:integer"   json:"virustotal_score"`
	VirusTotalLink  *string `gorm:"type:text"      json:"virustotal_link"`

	SafeBrowsingHit *bool          `gorm:"type:boolean"   json:"safe_browsing_hit"`
	ThreatTypes     pq.StringArray `gorm:"type:text[]"    json:"threat_types"`

	DomainAgeDays   *int       `gorm:"type:integer"   json:"domain_age_days"`
	DomainCreatedAt *time.Time `gorm:"type:timestamptz" json:"domain_created_at"`
	DomainAgeFlag   bool       `gorm:"type:boolean;default:false" json:"domain_age_flag"`

	ScannedAt time.Time `gorm:"autoCreateTime;index:,sort:desc" json:"scanned_at"`
}
