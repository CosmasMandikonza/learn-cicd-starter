package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers http.Header
		wantKey string
		wantErr error
	}{
		"valid ApiKey header": {
			headers: http.Header{"Authorization": {"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
			wantErr: nil,
		},
		"no Authorization header": {
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		"empty Authorization header value": {
			headers: http.Header{"Authorization": {""}},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		"missing key after ApiKey prefix": {
			headers: http.Header{"Authorization": {"ApiKey"}},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		"wrong authorization scheme": {
			headers: http.Header{"Authorization": {"Bearer some-token"}},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		"prefix is case-sensitive": {
			headers: http.Header{"Authorization": {"apikey some-token"}},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		"only first token after prefix is returned": {
			headers: http.Header{"Authorization": {"ApiKey first second"}},
			wantKey: "first",
			wantErr: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tc.headers)

			if gotKey != tc.wantKey {
				t.Errorf("key: got %q, want %q", gotKey, tc.wantKey)
			}

			switch {
			case tc.wantErr == nil && gotErr != nil:
				t.Errorf("error: got %v, want nil", gotErr)
			case tc.wantErr != nil && gotErr == nil:
				t.Errorf("error: got nil, want %q", tc.wantErr)
			case tc.wantErr != nil && gotErr.Error() != tc.wantErr.Error():
				t.Errorf("error: got %q, want %q", gotErr, tc.wantErr)
			}
		})
	}
}

// TestGetAPIKey_SentinelError documents that callers can match the
// "missing header" case with errors.Is against the exported sentinel.
func TestGetAPIKey_SentinelError(t *testing.T) {
	_, err := GetAPIKey(http.Header{})
	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Errorf("expected errors.Is(err, ErrNoAuthHeaderIncluded) to be true, got err = %v", err)
	}
}
