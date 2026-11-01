// Package domain contains the core threat intelligence model and validation rules.
package domain

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	CategoryUnknown    = "unknown"
	CategoryMalware    = "malware"
	CategoryPhishing   = "phishing"
	CategoryRansomware = "ransomware"
	CategoryExploit    = "exploit"
	CategorySuspicious = "suspicious"

	SeverityUnknown  = "unknown"
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

var (
	md5Pattern = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

	ErrInvalidMD5        = errors.New("md5 must contain exactly 32 hexadecimal characters")
	ErrInvalidName       = errors.New("name is required and must not exceed 255 characters")
	ErrInvalidCategory   = errors.New("category has an unsupported value")
	ErrInvalidSeverity   = errors.New("severity has an unsupported value")
	ErrInvalidConfidence = errors.New("confidence must be between 0 and 100")
	ErrInvalidTags       = errors.New("tags must contain at most 20 non-empty values of up to 64 characters")
	ErrInvalidText       = errors.New("description, family and source exceed the allowed length")
)

// Threat describes a file-related threat intelligence record.
type Threat struct {
	MD5         string    `json:"md5"`
	Name        string    `json:"name"`
	Category    string    `json:"category"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Family      string    `json:"family"`
	Confidence  int       `json:"confidence"`
	Source      string    `json:"source"`
	Tags        []string  `json:"tags"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CreateThreatInput contains fields accepted when creating a threat.
type CreateThreatInput struct {
	MD5         string   `json:"md5"`
	Name        string   `json:"name"`
	Category    string   `json:"category,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Description string   `json:"description,omitempty"`
	Family      string   `json:"family,omitempty"`
	Confidence  *int     `json:"confidence,omitempty"`
	Source      string   `json:"source,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// UpdateThreatInput represents a full replacement of the editable threat fields.
// Fields omitted from a PUT request are reset to their defaults.
type UpdateThreatInput struct {
	Name        string   `json:"name"`
	Category    string   `json:"category,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Description string   `json:"description,omitempty"`
	Family      string   `json:"family,omitempty"`
	Confidence  *int     `json:"confidence,omitempty"`
	Source      string   `json:"source,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// NormalizeMD5 validates and normalizes an MD5 hash to lowercase.
func NormalizeMD5(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !md5Pattern.MatchString(value) {
		return "", ErrInvalidMD5
	}
	return strings.ToLower(value), nil
}

// NewThreat validates and converts a create request into the domain model.
func NewThreat(input CreateThreatInput, now time.Time) (Threat, error) {
	md5, err := NormalizeMD5(input.MD5)
	if err != nil {
		return Threat{}, err
	}

	threat := Threat{
		MD5:         md5,
		Name:        strings.TrimSpace(input.Name),
		Category:    defaultString(input.Category, CategoryUnknown),
		Severity:    defaultString(input.Severity, SeverityUnknown),
		Description: strings.TrimSpace(input.Description),
		Family:      strings.TrimSpace(input.Family),
		Source:      strings.TrimSpace(input.Source),
		Tags:        normalizeTags(input.Tags),
		CreatedAt:   now.UTC(),
		UpdatedAt:   now.UTC(),
	}
	if input.Confidence != nil {
		threat.Confidence = *input.Confidence
	}

	if err := ValidateThreat(threat); err != nil {
		return Threat{}, err
	}
	return threat, nil
}

// ApplyUpdate creates a replacement model while preserving the identity and creation time.
func (t Threat) ApplyUpdate(input UpdateThreatInput, now time.Time) (Threat, error) {
	updated := Threat{
		MD5:         t.MD5,
		Name:        strings.TrimSpace(input.Name),
		Category:    defaultString(input.Category, CategoryUnknown),
		Severity:    defaultString(input.Severity, SeverityUnknown),
		Description: strings.TrimSpace(input.Description),
		Family:      strings.TrimSpace(input.Family),
		Source:      strings.TrimSpace(input.Source),
		Tags:        normalizeTags(input.Tags),
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   now.UTC(),
	}
	if input.Confidence != nil {
		updated.Confidence = *input.Confidence
	}
	if err := ValidateThreat(updated); err != nil {
		return Threat{}, err
	}
	return updated, nil
}

// ValidateThreat validates all fields that can be stored in the database.
func ValidateThreat(t Threat) error {
	if _, err := NormalizeMD5(t.MD5); err != nil {
		return err
	}
	if t.Name == "" || len([]rune(t.Name)) > 255 {
		return ErrInvalidName
	}
	if !oneOf(t.Category, CategoryUnknown, CategoryMalware, CategoryPhishing, CategoryRansomware, CategoryExploit, CategorySuspicious) {
		return ErrInvalidCategory
	}
	if !oneOf(t.Severity, SeverityUnknown, SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical) {
		return ErrInvalidSeverity
	}
	if t.Confidence < 0 || t.Confidence > 100 {
		return ErrInvalidConfidence
	}
	if len([]rune(t.Description)) > 4000 || len([]rune(t.Family)) > 255 || len([]rune(t.Source)) > 255 {
		return ErrInvalidText
	}
	if len(t.Tags) > 20 {
		return ErrInvalidTags
	}
	for _, tag := range t.Tags {
		if strings.TrimSpace(tag) == "" || len([]rune(tag)) > 64 {
			return ErrInvalidTags
		}
	}
	return nil
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeTags(tags []string) []string {
	if len(tags) == 0 {
		return []string{}
	}
	result := make([]string, 0, len(tags))
	for _, tag := range tags {
		result = append(result, strings.TrimSpace(tag))
	}
	return result
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

// ValidationMessage returns a stable, client-safe validation message.
func ValidationMessage(err error) string {
	switch {
	case errors.Is(err, ErrInvalidMD5):
		return "Invalid MD5 hash"
	case errors.Is(err, ErrInvalidName):
		return "Name is required and must not exceed 255 characters"
	case errors.Is(err, ErrInvalidCategory):
		return "Unsupported threat category"
	case errors.Is(err, ErrInvalidSeverity):
		return "Unsupported severity"
	case errors.Is(err, ErrInvalidConfidence):
		return "Confidence must be between 0 and 100"
	case errors.Is(err, ErrInvalidTags):
		return "Tags must contain at most 20 non-empty values of up to 64 characters"
	case errors.Is(err, ErrInvalidText):
		return "One or more text fields exceed the allowed length"
	default:
		return fmt.Sprintf("Invalid threat data: %v", err)
	}
}
