package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"threat-intel-service/internal/domain"
	"threat-intel-service/internal/repository"
)

const validMD5 = "d41d8cd98f00b204e9800998ecf8427e"

func newTestServer() http.Handler {
	repo := repository.NewMemoryRepository()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewHandler(repo, logger).Routes()
}

func request(t *testing.T, handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = bytes.NewBufferString(body)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func TestCreateGetAndUpdateThreat(t *testing.T) {
	handler := newTestServer()
	createBody := `{"md5":"` + validMD5 + `","name":"Trojan.Win32.Generic","category":"malware","severity":"high","description":"Test threat","family":"Generic","confidence":95,"source":"sandbox","tags":["windows","trojan"]}`

	created := request(t, handler, http.MethodPost, "/info", createBody)
	if created.Code != http.StatusCreated {
		t.Fatalf("create: got status %d, body %s", created.Code, created.Body.String())
	}

	var createdThreat domain.Threat
	if err := json.Unmarshal(created.Body.Bytes(), &createdThreat); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if createdThreat.MD5 != validMD5 || createdThreat.Confidence != 95 || len(createdThreat.Tags) != 2 {
		t.Fatalf("unexpected created threat: %+v", createdThreat)
	}
	if createdThreat.CreatedAt.IsZero() || createdThreat.UpdatedAt.IsZero() {
		t.Fatal("timestamps must be populated")
	}

	got := request(t, handler, http.MethodGet, "/info/"+validMD5, "")
	if got.Code != http.StatusOK {
		t.Fatalf("get: got status %d, body %s", got.Code, got.Body.String())
	}

	updated := request(t, handler, http.MethodPut, "/info/"+validMD5, `{"name":"Updated threat","severity":"critical"}`)
	if updated.Code != http.StatusOK {
		t.Fatalf("update: got status %d, body %s", updated.Code, updated.Body.String())
	}
	var updatedThreat domain.Threat
	if err := json.Unmarshal(updated.Body.Bytes(), &updatedThreat); err != nil {
		t.Fatalf("decode update response: %v", err)
	}
	if updatedThreat.Name != "Updated threat" || updatedThreat.Severity != domain.SeverityCritical {
		t.Fatalf("unexpected updated threat: %+v", updatedThreat)
	}
	if updatedThreat.Category != domain.CategoryUnknown || len(updatedThreat.Tags) != 0 {
		t.Fatalf("PUT must replace omitted optional fields with defaults: %+v", updatedThreat)
	}
}

func TestCreateDuplicateReturnsConflict(t *testing.T) {
	handler := newTestServer()
	body := `{"md5":"` + validMD5 + `","name":"First"}`
	if response := request(t, handler, http.MethodPost, "/info", body); response.Code != http.StatusCreated {
		t.Fatalf("first create: got %d", response.Code)
	}
	response := request(t, handler, http.MethodPost, "/info", body)
	if response.Code != http.StatusConflict {
		t.Fatalf("second create: got %d, want %d", response.Code, http.StatusConflict)
	}
}

func TestValidationAndNotFoundStatuses(t *testing.T) {
	handler := newTestServer()

	invalidMD5 := request(t, handler, http.MethodGet, "/info/not-an-md5", "")
	if invalidMD5.Code != http.StatusBadRequest {
		t.Fatalf("invalid MD5: got %d, want 400", invalidMD5.Code)
	}

	missing := request(t, handler, http.MethodGet, "/info/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "")
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing record: got %d, want 404", missing.Code)
	}

	invalidConfidence := request(t, handler, http.MethodPost, "/info", `{"md5":"`+validMD5+`","name":"Bad","confidence":101}`)
	if invalidConfidence.Code != http.StatusBadRequest {
		t.Fatalf("invalid confidence: got %d, want 400", invalidConfidence.Code)
	}
}

func TestRejectsMalformedUnknownAndNonJSONBodies(t *testing.T) {
	handler := newTestServer()
	cases := []struct {
		name        string
		contentType string
		body        string
		wantStatus  int
	}{
		{name: "malformed JSON", contentType: "application/json", body: `{"md5":`, wantStatus: http.StatusBadRequest},
		{name: "unknown field", contentType: "application/json", body: `{"md5":"` + validMD5 + `","name":"x","unexpected":true}`, wantStatus: http.StatusBadRequest},
		{name: "wrong content type", contentType: "text/plain", body: `{}`, wantStatus: http.StatusUnsupportedMediaType},
		{name: "multiple JSON values", contentType: "application/json", body: `{} {}`, wantStatus: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/info", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != tc.wantStatus {
				t.Fatalf("got %d, want %d; body: %s", response.Code, tc.wantStatus, response.Body.String())
			}
		})
	}
}

func TestAPIKeyMiddleware(t *testing.T) {
	handler := APIKeyMiddleware("secret", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	withoutKey := httptest.NewRecorder()
	handler.ServeHTTP(withoutKey, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if withoutKey.Code != http.StatusUnauthorized {
		t.Fatalf("without API key: got %d, want 401", withoutKey.Code)
	}

	withKeyRequest := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	withKeyRequest.Header.Set("X-API-Key", "secret")
	withKey := httptest.NewRecorder()
	handler.ServeHTTP(withKey, withKeyRequest)
	if withKey.Code != http.StatusNoContent {
		t.Fatalf("with API key: got %d, want 204", withKey.Code)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	calls := 0
	handler := RateLimitMiddleware(1, timeMinute(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/", nil))
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/", nil))
	if first.Code != http.StatusNoContent || second.Code != http.StatusTooManyRequests || calls != 1 {
		t.Fatalf("unexpected rate limit result: first=%d second=%d calls=%d", first.Code, second.Code, calls)
	}
}

func timeMinute() time.Duration { return time.Minute }
