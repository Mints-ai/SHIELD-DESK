package main

import (
	"encoding/json"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestManualRollbackHTTPRunsRecovery(t *testing.T) {
	s := NewPatchServer(t.TempDir())
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/jobs", strings.NewReader(`{"host":"simulated.local","package":"openssl","target_version":"2.0.0","dry_run":true}`)))
	if response.Code != http.StatusCreated {
		t.Fatal(response.Body.String())
	}
	var created struct {
		JobID string `json:"job_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	rec, ok := s.store.get(created.JobID)
	if !ok {
		t.Fatal("job missing")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		rec.mu.RLock()
		ready := rec.RollbackReady
		errText := rec.Error
		rec.mu.RUnlock()
		if ready {
			break
		}
		if errText != "" {
			t.Fatal(errText)
		}
		if time.Now().After(deadline) {
			t.Fatal("patch did not become rollback-ready")
		}
		time.Sleep(time.Millisecond)
	}
	response = httptest.NewRecorder()
	s.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+created.JobID+"/rollback", nil))
	if response.Code != http.StatusAccepted {
		t.Fatal(response.Body.String())
	}
	for {
		rec.mu.RLock()
		pending := rec.RollbackPending
		errText := rec.Error
		orch := rec.Orch
		rec.mu.RUnlock()
		if !pending {
			if errText != "" {
				t.Fatal(errText)
			}
			if orch.State() != models.StateRolledBackHumanReview {
				t.Fatal(orch.State())
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("rollback did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	response = httptest.NewRecorder()
	s.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+created.JobID+"/rollback", nil))
	if response.Code != http.StatusConflict {
		t.Fatalf("duplicate request returned %d", response.Code)
	}
}

func TestLiveRollbackRequiresServiceAuthentication(t *testing.T) {
	s := NewPatchServer(t.TempDir())
	s.store.set(&JobRecord{Job: &models.PatchJob{JobID: "live-job"}})
	t.Setenv("PATCH_ORCHESTRATOR_API_TOKEN", "expected-service-token")
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/jobs/live-job/rollback", nil))
	if response.Code != http.StatusForbidden {
		t.Fatal("live rollback accepted without its service token")
	}
	response = httptest.NewRecorder()
	s.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/jobs/missing/rollback", nil))
	if response.Code != http.StatusNotFound {
		t.Fatal("missing job should be rejected")
	}
}
