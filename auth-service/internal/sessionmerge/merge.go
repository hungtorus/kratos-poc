// Package sessionmerge appends authentication methods to an existing Kratos session.
// OIDC refresh login completes in ProcessLogin with a new inactive session, so step-up
// must merge oidc into the prior API session the user already holds.
package sessionmerge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

type AuthMethod struct {
	Method      string    `json:"method"`
	AAL         string    `json:"aal"`
	Provider    string    `json:"provider,omitempty"`
	CompletedAt time.Time `json:"completed_at"`
}

// AppendMethod adds an authentication method to the session AMR if not already present.
func AppendMethod(ctx context.Context, dsn, sessionID string, method AuthMethod) (appended bool, err error) {
	if dsn == "" || sessionID == "" {
		return false, fmt.Errorf("session merge: missing dsn or session id")
	}
	if method.CompletedAt.IsZero() {
		method.CompletedAt = time.Now().UTC()
	}
	payload, err := json.Marshal(method)
	if err != nil {
		return false, err
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return false, err
	}
	defer db.Close()

	var exists bool
	err = db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM sessions s,
			     jsonb_array_elements(COALESCE(s.authentication_methods, '[]'::jsonb)) elem
			WHERE s.id = $1::uuid
			  AND elem->>'method' = $2
			  AND COALESCE(elem->>'provider', '') = $3
		)`, sessionID, method.Method, method.Provider).Scan(&exists)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}

	res, err := db.ExecContext(ctx, `
		UPDATE sessions
		SET authentication_methods = COALESCE(authentication_methods, '[]'::jsonb) || $2::jsonb,
		    authenticated_at = $3,
		    updated_at = $3
		WHERE id = $1::uuid`,
		sessionID, fmt.Sprintf("[%s]", payload), method.CompletedAt.UTC())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
