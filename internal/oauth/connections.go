package oauth

import "context"

type grantContextKey struct{}

// WithGrant carries the connection that authenticated this request across the MCP transport.
func WithGrant(ctx context.Context, g Grant) context.Context {
	return context.WithValue(ctx, grantContextKey{}, g)
}

func GrantFamily(ctx context.Context) string {
	g, _ := ctx.Value(grantContextKey{}).(Grant)
	return g.FamilyID
}

// Connection is the information shown to the owner for one consent decision.
type Connection struct {
	FamilyID string
	Name     string
	Scope    string
}

func (s *Store) Connections(ctx context.Context) ([]Connection, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT t.family_id, t.client_id, COALESCE(c.name, t.client_id), t.scope
		FROM oauth_tokens t LEFT JOIN oauth_clients c ON c.client_id=t.client_id
		WHERE t.kind='refresh' AND t.rotated_at=0 AND t.revoked_at=0 AND t.expires_at>?
		ORDER BY 3, t.family_id`, s.now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Connection
	for rows.Next() {
		var c Connection
		var clientID string
		if err := rows.Scan(&c.FamilyID, &clientID, &c.Name, &c.Scope); err != nil {
			return nil, err
		}
		if p, ok := publishedClients[clientID]; ok {
			c.Name = p.name
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

func (s *Store) RevokeConnection(ctx context.Context, family string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.ExecContext(ctx, "DELETE FROM oauth_tokens WHERE family_id=?", family)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrInvalidGrant
	}
	return nil
}

// ConnectionActive also covers automatic family revocation after refresh-token reuse.
func (s *Store) ConnectionActive(ctx context.Context, family string) bool {
	var active bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM oauth_tokens
		WHERE family_id=? AND kind='refresh' AND rotated_at=0 AND revoked_at=0 AND expires_at>?)`, family, s.now().Unix()).Scan(&active)
	return err == nil && active
}
