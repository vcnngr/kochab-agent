package transport

import "fmt"

// clientError represents a non-retryable HTTP client error (4xx).
type clientError struct {
	status int
	body   string
}

func (e *clientError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.status, e.body)
}
