// Package httpapi implements the REST transport layer.
package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"threat-intel-service/internal/domain"
	"threat-intel-service/internal/repository"
)

const maxRequestBody = 1 << 20 // 1 MiB

type Handler struct {
	repo   repository.ThreatRepository
	logger *slog.Logger
	now    func() time.Time
}

func NewHandler(repo repository.ThreatRepository, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{repo: repo, logger: logger, now: time.Now}
}

// Routes returns the service routes. Go 1.22+ method-aware ServeMux patterns are used.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.health)
	mux.HandleFunc("GET /info/{md5}", h.getInfoByMD5)
	mux.HandleFunc("PUT /info/{md5}", h.updateThreat)
	mux.HandleFunc("POST /info", h.createThreat)
	return mux
}

func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) getInfoByMD5(w http.ResponseWriter, r *http.Request) {
	md5, err := domain.NormalizeMD5(r.PathValue("md5"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid MD5 hash", err.Error())
		return
	}

	threat, err := h.repo.Get(r.Context(), md5)
	if err != nil {
		h.handleRepositoryError(w, r, err, md5)
		return
	}
	writeJSON(w, http.StatusOK, threat)
}

func (h *Handler) createThreat(w http.ResponseWriter, r *http.Request) {
	var input domain.CreateThreatInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeDecodeError(w, err)
		return
	}

	threat, err := domain.NewThreat(input, h.now())
	if err != nil {
		writeError(w, http.StatusBadRequest, domain.ValidationMessage(err), err.Error())
		return
	}

	created, err := h.repo.Create(r.Context(), threat)
	if err != nil {
		h.handleRepositoryError(w, r, err, threat.MD5)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (h *Handler) updateThreat(w http.ResponseWriter, r *http.Request) {
	md5, err := domain.NormalizeMD5(r.PathValue("md5"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid MD5 hash", err.Error())
		return
	}

	var input domain.UpdateThreatInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeDecodeError(w, err)
		return
	}

	existing, err := h.repo.Get(r.Context(), md5)
	if err != nil {
		h.handleRepositoryError(w, r, err, md5)
		return
	}
	updated, err := existing.ApplyUpdate(input, h.now())
	if err != nil {
		writeError(w, http.StatusBadRequest, domain.ValidationMessage(err), err.Error())
		return
	}
	updated, err = h.repo.Update(r.Context(), updated)
	if err != nil {
		h.handleRepositoryError(w, r, err, md5)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (h *Handler) handleRepositoryError(w http.ResponseWriter, r *http.Request, err error, md5 string) {
	switch {
	case errors.Is(err, repository.ErrNotFound):
		writeError(w, http.StatusNotFound, "Threat not found", fmt.Sprintf("No threat with MD5 %s found", md5))
	case errors.Is(err, repository.ErrConflict):
		writeError(w, http.StatusConflict, "Threat already exists", fmt.Sprintf("A threat with MD5 %s already exists", md5))
	default:
		h.logger.Error("repository operation failed", "error", err, "path", r.URL.Path)
		writeError(w, http.StatusInternalServerError, "Internal server error", "An unexpected error occurred")
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	contentType := strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])
	if contentType != "application/json" {
		return errUnsupportedMediaType
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain a single JSON object")
		}
		return err
	}
	return nil
}

var errUnsupportedMediaType = errors.New("Content-Type must be application/json")

func writeDecodeError(w http.ResponseWriter, err error) {
	var maxBytesError *http.MaxBytesError
	switch {
	case errors.Is(err, errUnsupportedMediaType):
		writeError(w, http.StatusUnsupportedMediaType, "Unsupported media type", err.Error())
	case errors.As(err, &maxBytesError):
		writeError(w, http.StatusRequestEntityTooLarge, "Request body too large", "Maximum request body size is 1 MiB")
	default:
		writeError(w, http.StatusBadRequest, "Invalid JSON request", err.Error())
	}
}

type errorResponse struct {
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func writeError(w http.ResponseWriter, status int, message, details string) {
	writeJSON(w, status, errorResponse{Message: message, Details: details})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		slog.Error("failed to encode HTTP response", "error", err)
	}
}
