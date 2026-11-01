package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"threat-intel-service/internal/domain"
	"threat-intel-service/internal/repository"
)

// PostgresRepository persists threat records in PostgreSQL.
type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (r *PostgresRepository) Get(ctx context.Context, md5 string) (domain.Threat, error) {
	threat, err := scanThreat(r.pool.QueryRow(ctx, selectThreatSQL+` WHERE md5 = $1`, md5))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Threat{}, repository.ErrNotFound
	}
	if err != nil {
		return domain.Threat{}, fmt.Errorf("select threat: %w", err)
	}
	return threat, nil
}

func (r *PostgresRepository) Create(ctx context.Context, threat domain.Threat) (domain.Threat, error) {
	query := `INSERT INTO threats (md5, name, category, severity, description, family, confidence, source, tags, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING md5, name, category, severity, description, family, confidence, source, tags, created_at, updated_at`
	created, err := scanThreat(r.pool.QueryRow(ctx, query,
		threat.MD5, threat.Name, threat.Category, threat.Severity, threat.Description,
		threat.Family, threat.Confidence, threat.Source, threat.Tags, threat.CreatedAt, threat.UpdatedAt,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return domain.Threat{}, repository.ErrConflict
		}
		return domain.Threat{}, fmt.Errorf("insert threat: %w", err)
	}
	return created, nil
}

func (r *PostgresRepository) Update(ctx context.Context, threat domain.Threat) (domain.Threat, error) {
	query := `UPDATE threats SET name=$2, category=$3, severity=$4, description=$5, family=$6,
		confidence=$7, source=$8, tags=$9, updated_at=$10
		WHERE md5=$1
		RETURNING md5, name, category, severity, description, family, confidence, source, tags, created_at, updated_at`
	updated, err := scanThreat(r.pool.QueryRow(ctx, query,
		threat.MD5, threat.Name, threat.Category, threat.Severity, threat.Description,
		threat.Family, threat.Confidence, threat.Source, threat.Tags, threat.UpdatedAt,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Threat{}, repository.ErrNotFound
	}
	if err != nil {
		return domain.Threat{}, fmt.Errorf("update threat: %w", err)
	}
	return updated, nil
}

const selectThreatSQL = `SELECT md5, name, category, severity, description, family, confidence, source, tags, created_at, updated_at FROM threats`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanThreat(row rowScanner) (domain.Threat, error) {
	var threat domain.Threat
	err := row.Scan(
		&threat.MD5, &threat.Name, &threat.Category, &threat.Severity,
		&threat.Description, &threat.Family, &threat.Confidence, &threat.Source,
		&threat.Tags, &threat.CreatedAt, &threat.UpdatedAt,
	)
	if threat.Tags == nil {
		threat.Tags = []string{}
	}
	return threat, err
}
