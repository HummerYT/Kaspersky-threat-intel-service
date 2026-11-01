package domain

import (
	"errors"
	"testing"
	"time"
)

func TestNormalizeMD5(t *testing.T) {
	got, err := NormalizeMD5("D41D8CD98F00B204E9800998ECF8427E")
	if err != nil {
		t.Fatalf("NormalizeMD5 returned error: %v", err)
	}
	if got != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Fatalf("unexpected normalized MD5: %s", got)
	}
	if _, err := NormalizeMD5("abc"); !errors.Is(err, ErrInvalidMD5) {
		t.Fatalf("expected ErrInvalidMD5, got %v", err)
	}
}

func TestNewThreatDefaultsAndValidation(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	threat, err := NewThreat(CreateThreatInput{MD5: "D41D8CD98F00B204E9800998ECF8427E", Name: "  Test  "}, now)
	if err != nil {
		t.Fatalf("NewThreat returned error: %v", err)
	}
	if threat.Name != "Test" || threat.Category != CategoryUnknown || threat.Severity != SeverityUnknown || threat.Confidence != 0 {
		t.Fatalf("unexpected default values: %+v", threat)
	}
	if !threat.CreatedAt.Equal(now) || !threat.UpdatedAt.Equal(now) {
		t.Fatal("timestamps should use supplied clock")
	}

	confidence := 101
	_, err = NewThreat(CreateThreatInput{MD5: "d41d8cd98f00b204e9800998ecf8427e", Name: "Bad", Confidence: &confidence}, now)
	if !errors.Is(err, ErrInvalidConfidence) {
		t.Fatalf("expected ErrInvalidConfidence, got %v", err)
	}
}
