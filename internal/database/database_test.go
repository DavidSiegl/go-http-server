package database

import (
	"context"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func newMock(t *testing.T) (*Queries, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db), mock
}

func TestNew(t *testing.T) {
	q, _ := newMock(t)
	if q == nil {
		t.Fatal("New returned nil")
	}
}

func TestCreateUser(t *testing.T) {
	q, mock := newMock(t)
	id := uuid.New()
	now := time.Now()

	rows := sqlmock.NewRows([]string{"id", "created_at", "updated_at", "email", "hashed_password"}).
		AddRow(id, now, now, "test@example.com", "hash")
	mock.ExpectQuery("INSERT INTO users").
		WithArgs("test@example.com", "hash").
		WillReturnRows(rows)

	user, err := q.CreateUser(context.Background(), CreateUserParams{
		Email:          "test@example.com",
		HashedPassword: "hash",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if user.Email != "test@example.com" {
		t.Errorf("email = %q, want %q", user.Email, "test@example.com")
	}
	if user.ID != id {
		t.Errorf("id = %v, want %v", user.ID, id)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestGetUserByEmail(t *testing.T) {
	q, mock := newMock(t)
	id := uuid.New()
	now := time.Now()

	rows := sqlmock.NewRows([]string{"id", "created_at", "updated_at", "email", "hashed_password"}).
		AddRow(id, now, now, "find@example.com", "hash")
	mock.ExpectQuery("SELECT .* FROM users WHERE email").
		WithArgs("find@example.com").
		WillReturnRows(rows)

	user, err := q.GetUserByEmail(context.Background(), "find@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if user.Email != "find@example.com" {
		t.Errorf("email = %q, want %q", user.Email, "find@example.com")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestDeleteAllUsers(t *testing.T) {
	q, mock := newMock(t)

	mock.ExpectExec("DELETE FROM users").WillReturnResult(sqlmock.NewResult(0, 3))

	if err := q.DeleteAllUsers(context.Background()); err != nil {
		t.Fatalf("DeleteAllUsers: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestCreateChirp(t *testing.T) {
	q, mock := newMock(t)
	chirpID := uuid.New()
	userID := uuid.New()
	now := time.Now()

	rows := sqlmock.NewRows([]string{"id", "created_at", "updated_at", "body", "user_id"}).
		AddRow(chirpID, now, now, "hello world", userID)
	mock.ExpectQuery("INSERT INTO chirps").
		WithArgs("hello world", userID).
		WillReturnRows(rows)

	chirp, err := q.CreateChirp(context.Background(), CreateChirpParams{
		Body:   "hello world",
		UserID: userID,
	})
	if err != nil {
		t.Fatalf("CreateChirp: %v", err)
	}
	if chirp.Body != "hello world" {
		t.Errorf("body = %q, want %q", chirp.Body, "hello world")
	}
	if chirp.UserID != userID {
		t.Errorf("user_id = %v, want %v", chirp.UserID, userID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestGetChirp(t *testing.T) {
	q, mock := newMock(t)
	chirpID := uuid.New()
	userID := uuid.New()
	now := time.Now()

	rows := sqlmock.NewRows([]string{"id", "created_at", "updated_at", "body", "user_id"}).
		AddRow(chirpID, now, now, "test chirp", userID)
	mock.ExpectQuery("SELECT .* FROM chirps WHERE id").
		WithArgs(chirpID).
		WillReturnRows(rows)

	chirp, err := q.GetChirp(context.Background(), chirpID)
	if err != nil {
		t.Fatalf("GetChirp: %v", err)
	}
	if chirp.ID != chirpID {
		t.Errorf("id = %v, want %v", chirp.ID, chirpID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestGetChirps(t *testing.T) {
	q, mock := newMock(t)
	id1, id2 := uuid.New(), uuid.New()
	userID := uuid.New()
	now := time.Now()

	rows := sqlmock.NewRows([]string{"id", "created_at", "updated_at", "body", "user_id"}).
		AddRow(id1, now, now, "first", userID).
		AddRow(id2, now, now, "second", userID)
	mock.ExpectQuery("SELECT .* FROM chirps").WillReturnRows(rows)

	chirps, err := q.GetChirps(context.Background())
	if err != nil {
		t.Fatalf("GetChirps: %v", err)
	}
	if len(chirps) != 2 {
		t.Fatalf("got %d chirps, want 2", len(chirps))
	}
	if chirps[0].Body != "first" || chirps[1].Body != "second" {
		t.Errorf("unexpected bodies: %q, %q", chirps[0].Body, chirps[1].Body)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}
