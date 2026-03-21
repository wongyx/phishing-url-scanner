package checker

import "fmt"

type ErrRateLimited struct {
	API        string
	RetryAfter string
}

func (e *ErrRateLimited) Error() string {
	return fmt.Sprintf("%s rate limited (retry after: %s)", e.API, e.RetryAfter)
}

type ErrAPIUnavailable struct {
	API    string
	Status int
}

func (e *ErrAPIUnavailable) Error() string {
	return fmt.Sprintf("%s unavailable (status: %d)", e.API, e.Status)
}

type ErrInvalidURL struct {
	URL    string
	Reason string
}

func (e *ErrInvalidURL) Error() string {
	return fmt.Sprintf("invalid URL %q: %s", e.URL, e.Reason)
}
