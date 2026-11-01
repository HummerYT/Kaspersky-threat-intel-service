package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"threat-intel-service/internal/domain"
	"threat-intel-service/internal/repository"
)

// TestPostgresRepositoryCRUD exercises the PostgreSQL repository against a real database.
// It is skipped unless TEST_DATABASE_URL is set. For safety, the database name must end
// with "_test"; the test never deletes rows with a predefined or shared MD5 value.
func TestPostgresRepositoryCRUD(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set TEST_DATABASE_URL to run PostgreSQL integration tests")
	}

	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse TEST_DATABASE_URL: %v", err)
	}

	databaseName := strings.ToLower(strings.TrimSpace(poolConfig.ConnConfig.Database))
	if !strings.HasSuffix(databaseName, "_test") {
		t.Fatalf(
			"refusing to run PostgreSQL integration tests against database %q: database name must end with _test",
			databaseName,
		)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping PostgreSQL: %v", err)
	}
	if err := ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	md5 := newUniqueMD5(t)
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()

		if _, cleanupErr := pool.Exec(cleanupCtx, `DELETE FROM threats WHERE md5=$1`, md5); cleanupErr != nil {
			t.Errorf("clean up integration-test threat: %v", cleanupErr)
		}
	}()

	repo := NewPostgresRepository(pool)
	threat, err := domain.NewThreat(domain.CreateThreatInput{
		MD5: md5, Name: "Integration test threat", Category: domain.CategoryMalware,
		Severity: domain.SeverityHigh, Confidence: intPointer(90), Tags: []string{"integration", "test"},
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("build threat: %v", err)
	}

	created, err := repo.Create(ctx, threat)
	if err != nil {
		t.Fatalf("create threat: %v", err)
	}
	if created.MD5 != md5 || len(created.Tags) != 2 {
		t.Fatalf("unexpected created threat: %+v", created)
	}

	if _, err := repo.Create(ctx, threat); err != repository.ErrConflict {
		t.Fatalf("duplicate create: got %v, want repository.ErrConflict", err)
	}

	got, err := repo.Get(ctx, md5)
	if err != nil {
		t.Fatalf("get threat: %v", err)
	}
	if got.Name != threat.Name {
		t.Fatalf("get threat returned name %q, want %q", got.Name, threat.Name)
	}

	got.Name = "Updated integration threat"
	got.UpdatedAt = time.Now().UTC()
	updated, err := repo.Update(ctx, got)
	if err != nil {
		t.Fatalf("update threat: %v", err)
	}
	if updated.Name != "Updated integration threat" {
		t.Fatalf("unexpected updated name: %s", updated.Name)
	}

	if _, err := repo.Get(ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != repository.ErrNotFound {
		t.Fatalf("missing get: got %v, want repository.ErrNotFound", err)
	}
}

func newUniqueMD5(t *testing.T) string {
	t.Helper()

	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatalf("generate unique test MD5: %v", err)
	}
	return hex.EncodeToString(value[:])
}

func intPointer(value int) *int { return &value }
