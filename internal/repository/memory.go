package repository

import (
	"context"
	"sync"

	"threat-intel-service/internal/domain"
)

type MemoryRepository struct {
	mu      sync.RWMutex
	threats map[string]domain.Threat
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{threats: make(map[string]domain.Threat)}
}

func (r *MemoryRepository) Get(_ context.Context, md5 string) (domain.Threat, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	threat, ok := r.threats[md5]
	if !ok {
		return domain.Threat{}, ErrNotFound
	}
	return cloneThreat(threat), nil
}

func (r *MemoryRepository) Create(_ context.Context, threat domain.Threat) (domain.Threat, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.threats[threat.MD5]; exists {
		return domain.Threat{}, ErrConflict
	}
	r.threats[threat.MD5] = cloneThreat(threat)
	return cloneThreat(threat), nil
}

func (r *MemoryRepository) Update(_ context.Context, threat domain.Threat) (domain.Threat, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.threats[threat.MD5]; !exists {
		return domain.Threat{}, ErrNotFound
	}
	r.threats[threat.MD5] = cloneThreat(threat)
	return cloneThreat(threat), nil
}

func cloneThreat(threat domain.Threat) domain.Threat {
	cloned := threat
	cloned.Tags = append([]string{}, threat.Tags...)
	return cloned
}
