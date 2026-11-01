// Package repository defines persistence contracts and shared errors.
package repository

import (
	"context"
	"errors"

	"threat-intel-service/internal/domain"
)

var (
	ErrNotFound = errors.New("threat not found")
	ErrConflict = errors.New("threat already exists")
)

type ThreatRepository interface {
	Get(ctx context.Context, md5 string) (domain.Threat, error)
	Create(ctx context.Context, threat domain.Threat) (domain.Threat, error)
	Update(ctx context.Context, threat domain.Threat) (domain.Threat, error)
}
