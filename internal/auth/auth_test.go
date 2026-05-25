package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeAndValidateJWT(t *testing.T) {
	userID := uuid.New()
	secret := "test-secret"

	token, err := MakeJWT(userID, secret, time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT: %v", err)
	}

	got, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("ValidateJWT: %v", err)
	}
	if got != userID {
		t.Errorf("got %v, want %v", got, userID)
	}
}

func TestValidateJWT_WrongSecret(t *testing.T) {
	userID := uuid.New()

	token, err := MakeJWT(userID, "correct-secret", time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT: %v", err)
	}

	_, err = ValidateJWT(token, "wrong-secret")
	if err == nil {
		t.Fatal("expected error for wrong secret, got nil")
	}
}

func TestValidateJWT_Expired(t *testing.T) {
	userID := uuid.New()

	token, err := MakeJWT(userID, "secret", -time.Second)
	if err != nil {
		t.Fatalf("MakeJWT: %v", err)
	}

	_, err = ValidateJWT(token, "secret")
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

func TestHashAndCheckPassword(t *testing.T) {
	password := "hunter2"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	ok, err := CheckPasswordHash(password, hash)
	if err != nil {
		t.Fatalf("CheckPasswordHash: %v", err)
	}
	if !ok {
		t.Error("expected password to match hash")
	}
}

func TestMakeRefreshToken(t *testing.T) {
	a, err := MakeRefreshToken()
	if err != nil {
		t.Fatalf("MakeRefreshToken: %v", err)
	}
	if len(a) != 64 {
		t.Errorf("token length = %d, want 64 hex chars", len(a))
	}

	b, _ := MakeRefreshToken()
	if a == b {
		t.Error("two tokens should not be equal")
	}
}

func TestGetBearerToken(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		wantToken string
		wantErr   bool
	}{
		{
			name:      "valid token",
			header:    "Bearer my-secret-token",
			wantToken: "my-secret-token",
		},
		{
			name:      "extra whitespace around token",
			header:    "Bearer   spaced-token  ",
			wantToken: "spaced-token",
		},
		{
			name:    "missing header",
			header:  "",
			wantErr: true,
		},
		{
			name:    "wrong scheme",
			header:  "Basic dXNlcjpwYXNz",
			wantErr: true,
		},
		{
			name:    "bearer prefix only, no token",
			header:  "Bearer ",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.header != "" {
				h.Set("Authorization", tc.header)
			}
			got, err := GetBearerToken(h)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.wantToken {
				t.Errorf("got %q, want %q", got, tc.wantToken)
			}
		})
	}
}

func TestCheckPasswordHash_WrongPassword(t *testing.T) {
	hash, err := HashPassword("correct")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	ok, err := CheckPasswordHash("wrong", hash)
	if err != nil {
		t.Fatalf("CheckPasswordHash: %v", err)
	}
	if ok {
		t.Error("expected mismatch for wrong password")
	}
}
