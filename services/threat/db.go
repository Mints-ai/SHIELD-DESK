package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

type EventRepository struct {
	pool *pgxpool.Pool
}

func NewEventRepository(connString string) (*EventRepository, error) {
	if connString == "" {
		return &EventRepository{pool: nil}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		log.Warn().Err(err).Msg("[DB] TimescaleDB connection offline, continuing in development mode.")
		return &EventRepository{pool: nil}, nil
	}

	if err := pool.Ping(ctx); err != nil {
		log.Warn().Err(err).Msg("[DB] TimescaleDB ping failed, continuing in development mode.")
		return &EventRepository{pool: nil}, nil
	}

	log.Info().Msg("[DB] Connected to PostgreSQL / TimescaleDB successfully.")
	return &EventRepository{pool: pool}, nil
}

// WriteSecurityEvent inserts raw event into TimescaleDB security_events hypertable
func (r *EventRepository) WriteSecurityEvent(ctx context.Context, event *IngestEvent) error {
	if r.pool == nil {
		return nil
	}

	payloadJSON, err := json.Marshal(event.Payload)
	if err != nil {
		return err
	}

	eventTime := time.UnixMilli(event.Timestamp).UTC()
	query := `
		INSERT INTO public.security_events (time, tenant_id, asset_id, event_type, payload)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT DO NOTHING
	`
	_, err = r.pool.Exec(ctx, query, eventTime, event.TenantId, event.AssetId, event.EventType, payloadJSON)
	return err
}

// WriteAlert records a generated alert into the tenant's isolated alerts table
func (r *EventRepository) WriteAlert(ctx context.Context, alert *Alert) error {
	if r.pool == nil {
		return nil
	}

	payloadJSON, err := json.Marshal(alert.Payload)
	if err != nil {
		return err
	}

	// Schema-per-tenant insert: {tenant_id}.alerts
	query := fmt.Sprintf(`
		INSERT INTO %s.alerts (id, severity, type, status, rule_id, rule_name, payload, created_at)
		VALUES ($1, $2, $3, 'open', $4, $5, $6, $7)
	`, alert.TenantID)

	_, err = r.pool.Exec(ctx, query, alert.ID, alert.Severity, alert.Type, alert.RuleID, alert.RuleName, payloadJSON, alert.CreatedAt)
	if err != nil {
		// Fallback to public if tenant schema is not yet provisioned
		fallbackQuery := `
			INSERT INTO public.alerts (id, severity, type, status, rule_id, rule_name, payload, created_at)
			VALUES ($1, $2, $3, 'open', $4, $5, $6, $7)
			ON CONFLICT DO NOTHING
		`
		_, _ = r.pool.Exec(ctx, fallbackQuery, alert.ID, alert.Severity, alert.Type, alert.RuleID, alert.RuleName, payloadJSON, alert.CreatedAt)
	}
	return nil
}

func (r *EventRepository) Close() {
	if r.pool != nil {
		r.pool.Close()
	}
}
