package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"go-http-server/internal/auth"
	"go-http-server/internal/database"
)

const testSecret = "test-jwt-secret"

func newTestConfig(t *testing.T) (*apiConfig, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return &apiConfig{
		db:         database.New(db),
		platform:   "dev",
		jwt_secret: testSecret,
	}, mock
}

func makeToken(t *testing.T, userID uuid.UUID, expiry time.Duration) string {
	t.Helper()
	tok, err := auth.MakeJWT(userID, testSecret, expiry)
	if err != nil {
		t.Fatalf("MakeJWT: %v", err)
	}
	return tok
}

// --- readiness ---

func TestReadinessHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/healthz", nil)
	w := httptest.NewRecorder()
	readinessHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if body := w.Body.String(); body != "OK" {
		t.Errorf("body = %q, want %q", body, "OK")
	}
}

// --- metrics ---

func TestMetricsHandler(t *testing.T) {
	cfg, _ := newTestConfig(t)
	cfg.fileserverHits.Store(5)

	req := httptest.NewRequest(http.MethodGet, "/admin/metrics", nil)
	w := httptest.NewRecorder()
	cfg.metricsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "5") {
		t.Error("response body does not contain hit count")
	}
}

func TestMiddlewareMetricsInc(t *testing.T) {
	cfg, _ := newTestConfig(t)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := cfg.middlewareMetricsInc(inner)

	for i := 0; i < 3; i++ {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}
	if got := cfg.fileserverHits.Load(); got != 3 {
		t.Errorf("fileserverHits = %d, want 3", got)
	}
}

// --- reset ---

func TestResetHandler_Forbidden(t *testing.T) {
	cfg := &apiConfig{platform: "prod"}
	req := httptest.NewRequest(http.MethodPost, "/admin/reset", nil)
	w := httptest.NewRecorder()
	cfg.resetHandler(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestResetHandler_Dev(t *testing.T) {
	cfg, mock := newTestConfig(t)
	cfg.fileserverHits.Store(7)
	mock.ExpectExec("DELETE FROM users").WillReturnResult(sqlmock.NewResult(0, 0))

	req := httptest.NewRequest(http.MethodPost, "/admin/reset", nil)
	w := httptest.NewRecorder()
	cfg.resetHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if cfg.fileserverHits.Load() != 0 {
		t.Error("fileserverHits was not reset to 0")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// --- update user ---

func TestUpdateUserHandler_NoToken(t *testing.T) {
	cfg, _ := newTestConfig(t)
	req := httptest.NewRequest(http.MethodPut, "/api/users", strings.NewReader(`{"email":"a@b.com","password":"pw"}`))
	w := httptest.NewRecorder()
	cfg.updateUserHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestUpdateUserHandler_ExpiredToken(t *testing.T) {
	cfg, _ := newTestConfig(t)
	tok := makeToken(t, uuid.New(), -time.Second)
	req := httptest.NewRequest(http.MethodPut, "/api/users", strings.NewReader(`{"email":"a@b.com","password":"pw"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	cfg.updateUserHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestUpdateUserHandler_InvalidBody(t *testing.T) {
	cfg, _ := newTestConfig(t)
	tok := makeToken(t, uuid.New(), time.Hour)
	req := httptest.NewRequest(http.MethodPut, "/api/users", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	cfg.updateUserHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestUpdateUserHandler_Valid(t *testing.T) {
	cfg, mock := newTestConfig(t)
	userID := uuid.New()
	now := time.Now()
	tok := makeToken(t, userID, time.Hour)

	rows := sqlmock.NewRows([]string{"id", "created_at", "updated_at", "email", "hashed_password"}).
		AddRow(userID, now, now, "new@example.com", "hashed")
	mock.ExpectQuery("UPDATE users").
		WithArgs(userID, "new@example.com", sqlmock.AnyArg()).
		WillReturnRows(rows)

	payload, _ := json.Marshal(map[string]string{"email": "new@example.com", "password": "newpass"})
	req := httptest.NewRequest(http.MethodPut, "/api/users", strings.NewReader(string(payload)))
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	cfg.updateUserHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["email"] != "new@example.com" {
		t.Errorf("email = %v, want %q", resp["email"], "new@example.com")
	}
	if _, ok := resp["hashed_password"]; ok {
		t.Error("response must not include hashed_password")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// --- chirps ---

func TestCreateChirpHandler_NoToken(t *testing.T) {
	cfg, _ := newTestConfig(t)
	req := httptest.NewRequest(http.MethodPost, "/api/chirps", strings.NewReader(`{"body":"hello"}`))
	w := httptest.NewRecorder()
	cfg.createChirpHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestCreateChirpHandler_ExpiredToken(t *testing.T) {
	cfg, _ := newTestConfig(t)
	tok := makeToken(t, uuid.New(), -time.Second)
	req := httptest.NewRequest(http.MethodPost, "/api/chirps", strings.NewReader(`{"body":"hello"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	cfg.createChirpHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestCreateChirpHandler_InvalidBody(t *testing.T) {
	cfg, _ := newTestConfig(t)
	tok := makeToken(t, uuid.New(), time.Hour)
	req := httptest.NewRequest(http.MethodPost, "/api/chirps", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	cfg.createChirpHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestCreateChirpHandler_TooLong(t *testing.T) {
	cfg, _ := newTestConfig(t)
	tok := makeToken(t, uuid.New(), time.Hour)
	payload, _ := json.Marshal(map[string]any{"body": strings.Repeat("a", 141)})
	req := httptest.NewRequest(http.MethodPost, "/api/chirps", strings.NewReader(string(payload)))
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	cfg.createChirpHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestCreateChirpHandler_ProfanityReplaced(t *testing.T) {
	cfg, mock := newTestConfig(t)
	userID := uuid.New()
	chirpID := uuid.New()
	now := time.Now()
	tok := makeToken(t, userID, time.Hour)

	rows := sqlmock.NewRows([]string{"id", "created_at", "updated_at", "body", "user_id"}).
		AddRow(chirpID, now, now, "I love ****", userID)
	mock.ExpectQuery("INSERT INTO chirps").
		WithArgs("I love ****", userID).
		WillReturnRows(rows)

	payload, _ := json.Marshal(map[string]any{"body": "I love kerfuffle"})
	req := httptest.NewRequest(http.MethodPost, "/api/chirps", strings.NewReader(string(payload)))
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	cfg.createChirpHandler(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", w.Code, http.StatusCreated)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["body"] != "I love ****" {
		t.Errorf("body = %q, want profanity replaced", resp["body"])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestRefreshHandler_NoToken(t *testing.T) {
	cfg, _ := newTestConfig(t)
	req := httptest.NewRequest(http.MethodPost, "/api/refresh", nil)
	w := httptest.NewRecorder()
	cfg.refreshHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestRefreshHandler_InvalidToken(t *testing.T) {
	cfg, mock := newTestConfig(t)

	mock.ExpectQuery("SELECT users").
		WithArgs("bad-token").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at", "email", "hashed_password"}))

	req := httptest.NewRequest(http.MethodPost, "/api/refresh", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	w := httptest.NewRecorder()
	cfg.refreshHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestRefreshHandler_Valid(t *testing.T) {
	cfg, mock := newTestConfig(t)
	userID := uuid.New()
	now := time.Now()

	rows := sqlmock.NewRows([]string{"id", "created_at", "updated_at", "email", "hashed_password"}).
		AddRow(userID, now, now, "u@example.com", "hash")
	mock.ExpectQuery("SELECT users").
		WithArgs("valid-refresh-token").
		WillReturnRows(rows)

	req := httptest.NewRequest(http.MethodPost, "/api/refresh", nil)
	req.Header.Set("Authorization", "Bearer valid-refresh-token")
	w := httptest.NewRecorder()
	cfg.refreshHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["token"] == nil || resp["token"] == "" {
		t.Error("response missing token field")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestRevokeHandler_NoToken(t *testing.T) {
	cfg, _ := newTestConfig(t)
	req := httptest.NewRequest(http.MethodPost, "/api/revoke", nil)
	w := httptest.NewRecorder()
	cfg.revokeHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestRevokeHandler_Valid(t *testing.T) {
	cfg, mock := newTestConfig(t)

	mock.ExpectExec("UPDATE refresh_tokens").
		WithArgs("my-refresh-token").
		WillReturnResult(sqlmock.NewResult(0, 1))

	req := httptest.NewRequest(http.MethodPost, "/api/revoke", nil)
	req.Header.Set("Authorization", "Bearer my-refresh-token")
	w := httptest.NewRecorder()
	cfg.revokeHandler(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNoContent)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestDeleteChirpHandler_NoToken(t *testing.T) {
	cfg, _ := newTestConfig(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/chirps/"+uuid.New().String(), nil)
	req.SetPathValue("chirpID", uuid.New().String())
	w := httptest.NewRecorder()
	cfg.deleteChirpHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestDeleteChirpHandler_NotFound(t *testing.T) {
	cfg, mock := newTestConfig(t)
	userID := uuid.New()
	chirpID := uuid.New()
	tok := makeToken(t, userID, time.Hour)

	mock.ExpectQuery("SELECT .* FROM chirps WHERE id").
		WithArgs(chirpID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at", "body", "user_id"}))

	req := httptest.NewRequest(http.MethodDelete, "/api/chirps/"+chirpID.String(), nil)
	req.SetPathValue("chirpID", chirpID.String())
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	cfg.deleteChirpHandler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestDeleteChirpHandler_Forbidden(t *testing.T) {
	cfg, mock := newTestConfig(t)
	userID := uuid.New()
	otherUserID := uuid.New()
	chirpID := uuid.New()
	now := time.Now()
	tok := makeToken(t, userID, time.Hour)

	rows := sqlmock.NewRows([]string{"id", "created_at", "updated_at", "body", "user_id"}).
		AddRow(chirpID, now, now, "someone else's chirp", otherUserID)
	mock.ExpectQuery("SELECT .* FROM chirps WHERE id").
		WithArgs(chirpID).
		WillReturnRows(rows)

	req := httptest.NewRequest(http.MethodDelete, "/api/chirps/"+chirpID.String(), nil)
	req.SetPathValue("chirpID", chirpID.String())
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	cfg.deleteChirpHandler(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestDeleteChirpHandler_Valid(t *testing.T) {
	cfg, mock := newTestConfig(t)
	userID := uuid.New()
	chirpID := uuid.New()
	now := time.Now()
	tok := makeToken(t, userID, time.Hour)

	rows := sqlmock.NewRows([]string{"id", "created_at", "updated_at", "body", "user_id"}).
		AddRow(chirpID, now, now, "my chirp", userID)
	mock.ExpectQuery("SELECT .* FROM chirps WHERE id").
		WithArgs(chirpID).
		WillReturnRows(rows)
	mock.ExpectExec("DELETE FROM chirps").
		WithArgs(chirpID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	req := httptest.NewRequest(http.MethodDelete, "/api/chirps/"+chirpID.String(), nil)
	req.SetPathValue("chirpID", chirpID.String())
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	cfg.deleteChirpHandler(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNoContent)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestGetChirpHandler_InvalidUUID(t *testing.T) {
	cfg, _ := newTestConfig(t)
	req := httptest.NewRequest(http.MethodGet, "/api/chirps/not-a-uuid", nil)
	req.SetPathValue("chirpID", "not-a-uuid")
	w := httptest.NewRecorder()
	cfg.getChirpHandler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestGetChirpHandler_NotFound(t *testing.T) {
	cfg, mock := newTestConfig(t)
	chirpID := uuid.New()

	mock.ExpectQuery("SELECT .* FROM chirps WHERE id").
		WithArgs(chirpID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at", "body", "user_id"}))

	req := httptest.NewRequest(http.MethodGet, "/api/chirps/"+chirpID.String(), nil)
	req.SetPathValue("chirpID", chirpID.String())
	w := httptest.NewRecorder()
	cfg.getChirpHandler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

// --- users ---

func TestCreateUserHandler_InvalidBody(t *testing.T) {
	cfg, _ := newTestConfig(t)
	req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	cfg.createUserHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// --- login ---

func TestLoginHandler_InvalidBody(t *testing.T) {
	cfg, _ := newTestConfig(t)
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	cfg.loginHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestLoginHandler_BadCredentials(t *testing.T) {
	cfg, mock := newTestConfig(t)

	mock.ExpectQuery("SELECT .* FROM users WHERE email").
		WithArgs("nobody@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at", "email", "hashed_password"}))

	payload, _ := json.Marshal(map[string]string{"email": "nobody@example.com", "password": "wrong"})
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(string(payload)))
	w := httptest.NewRecorder()
	cfg.loginHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestLoginHandler_ReturnsTokens(t *testing.T) {
	cfg, mock := newTestConfig(t)
	userID := uuid.New()
	now := time.Now()

	hash, err := auth.HashPassword("secret123")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	userRows := sqlmock.NewRows([]string{"id", "created_at", "updated_at", "email", "hashed_password"}).
		AddRow(userID, now, now, "user@example.com", hash)
	mock.ExpectQuery("SELECT .* FROM users WHERE email").
		WithArgs("user@example.com").
		WillReturnRows(userRows)

	rtRows := sqlmock.NewRows([]string{"token", "created_at", "updated_at", "user_id", "expires_at", "revoked_at"}).
		AddRow("tok", now, now, userID, now.Add(60*24*time.Hour), nil)
	mock.ExpectQuery("INSERT INTO refresh_tokens").
		WillReturnRows(rtRows)

	payload, _ := json.Marshal(map[string]string{"email": "user@example.com", "password": "secret123"})
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(string(payload)))
	w := httptest.NewRecorder()
	cfg.loginHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["token"] == nil || resp["token"] == "" {
		t.Error("response missing token field")
	}
	if resp["refresh_token"] == nil || resp["refresh_token"] == "" {
		t.Error("response missing refresh_token field")
	}
	if resp["email"] != "user@example.com" {
		t.Errorf("email = %v, want %q", resp["email"], "user@example.com")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}
