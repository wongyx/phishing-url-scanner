package checker

import (
	"testing"
)

func TestErrRateLimited_Error(t *testing.T) {
	tests := []struct {
		name       string
		err        *ErrRateLimited
		wantSubstr string
	}{
		{
			name:       "with retry after",
			err:        &ErrRateLimited{API: "virustotal", RetryAfter: "60"},
			wantSubstr: "virustotal rate limited (retry after: 60)",
		},
		{
			name:       "without retry after",
			err:        &ErrRateLimited{API: "safebrowsing", RetryAfter: ""},
			wantSubstr: "safebrowsing rate limited (retry after: )",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.wantSubstr {
				t.Errorf("Error() = %q; want %q", got, tt.wantSubstr)
			}
		})
	}
}

func TestErrAPIUnavailable_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *ErrAPIUnavailable
		want string
	}{
		{
			name: "503",
			err:  &ErrAPIUnavailable{API: "virustotal", Status: 503},
			want: "virustotal unavailable (status: 503)",
		},
		{
			name: "500",
			err:  &ErrAPIUnavailable{API: "rdap", Status: 500},
			want: "rdap unavailable (status: 500)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.want {
				t.Errorf("Error() = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestErrInvalidURL_Error(t *testing.T) {
	err := &ErrInvalidURL{URL: "ftp://example.com", Reason: "scheme \"ftp\" not allowed, must be http or https"}
	got := err.Error()
	want := `invalid URL "ftp://example.com": scheme "ftp" not allowed, must be http or https`
	if got != want {
		t.Errorf("Error() = %q; want %q", got, want)
	}
}
