package transport

import (
	"errors"
	"fmt"
)

// clientError represents a non-retryable HTTP client error (4xx).
type clientError struct {
	status int
	body   string
}

func (e *clientError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.status, e.body)
}

// IsClientError reports whether err wraps a 4xx client error from the platform.
// 4xx errors are NOT buffered (the platform actively rejected the result).
func IsClientError(err error) bool {
	var ce *clientError
	return errors.As(err, &ce)
}

// ErrNodeDecommissioned is returned when the platform responds 410 GONE,
// indicating the node has been soft-deleted and the agent should stop polling.
var ErrNodeDecommissioned = errors.New("node_decommissioned")

// IsNodeDecommissioned reports whether err signals a 410 GONE response.
func IsNodeDecommissioned(err error) bool {
	return errors.Is(err, ErrNodeDecommissioned)
}
