package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/approval"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/audit"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/orchestrator"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/patch"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/precheck"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/rollback"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/snapshot"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/ssh"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/validation"
)

// JobRecord is an in-memory record of a job + its live streamed logs.
type JobRecord struct {
	mu          sync.RWMutex
	Job         *models.PatchJob
	Logs        []string
	Error       string
	Orch        *orchestrator.Orchestrator
	AuditWriter *audit.MemoryWriter
}

func (r *JobRecord) appendLog(msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ts := time.Now().Format("15:04:05")
	r.Logs = append(r.Logs, fmt.Sprintf("[%s] %s", ts, msg))
}

func (r *JobRecord) snapshot() (models.PatchJob, []string, string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	logs := make([]string, len(r.Logs))
	copy(logs, r.Logs)
	return *r.Job, logs, r.Error
}

// JobStore holds all in-flight and completed jobs.
type JobStore struct {
	mu   sync.RWMutex
	jobs map[string]*JobRecord
}

func NewJobStore() *JobStore {
	return &JobStore{
		jobs: make(map[string]*JobRecord),
	}
}

func (s *JobStore) set(record *JobRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[record.Job.JobID] = record
}

func (s *JobStore) get(id string) (*JobRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.jobs[id]
	return r, ok
}

func (s *JobStore) list() []models.PatchJob {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.PatchJob, 0, len(s.jobs))
	for _, r := range s.jobs {
		r.mu.RLock()
		out = append(out, *r.Job)
		r.mu.RUnlock()
	}
	return out
}

// CreateJobRequest is the incoming HTTP body to start a patch job.
type CreateJobRequest struct {
	Host               string   `json:"host"`
	Port               int      `json:"port"`
	User               string   `json:"user"`
	PrivateKeyPEM      string   `json:"private_key_pem"`
	HostKeyFingerprint string   `json:"host_key_fingerprint"`
	Package            string   `json:"package"`
	TargetVersion      string   `json:"target_version"`
	RestartServices    []string `json:"restart_services"`
	DryRun             bool     `json:"dry_run"`
}

// PatchServer is the HTTP API server wrapping the orchestrator.
type PatchServer struct {
	store    *JobStore
	auditDir string
}

func NewPatchServer(auditDir string) *PatchServer {
	return &PatchServer{
		store:    NewJobStore(),
		auditDir: auditDir,
	}
}

// jsonResponse writes a JSON HTTP response.
func jsonResponse(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// Handler routes.
func (s *PatchServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/v1/jobs", s.handleJobs)
	mux.HandleFunc("/api/v1/jobs/", s.handleJob)
	return mux
}

func (s *PatchServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"service":   "ShieldDesk SSH Patch Orchestrator (Go Backend API)",
		"status":    "running",
		"port":      8004,
		"ui_url":    "http://localhost:3000/dashboard/scanner",
		"message":   "This is the backend REST API microservice. Use the ShieldDesk UI at http://localhost:3000/dashboard/scanner to view and execute patches.",
		"endpoints": []string{"/health", "/api/v1/jobs"},
	})
}

func (s *PatchServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		jsonResponse(w, http.StatusOK, nil)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"service": "ssh-patch-orchestrator",
		"version": "1.0.0",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *PatchServer) handleJobs(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		jsonResponse(w, http.StatusOK, nil)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.listJobs(w, r)
	case http.MethodPost:
		s.createJob(w, r)
	default:
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *PatchServer) handleJob(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		jsonResponse(w, http.StatusOK, nil)
		return
	}
	// Trim prefix and split path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/jobs/")
	parts := strings.SplitN(path, "/", 2)
	jobID := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}

	switch {
	case r.Method == http.MethodGet && action == "":
		s.getJob(w, r, jobID)
	case r.Method == http.MethodPost && action == "rollback":
		s.triggerRollback(w, r, jobID)
	default:
		jsonResponse(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (s *PatchServer) listJobs(w http.ResponseWriter, r *http.Request) {
	jobs := s.store.list()
	// Include logs counts
	type jobSummary struct {
		models.PatchJob
		LogCount int `json:"log_count"`
	}
	out := make([]jobSummary, 0, len(jobs))
	for _, j := range jobs {
		rec, _ := s.store.get(j.JobID)
		var lc int
		if rec != nil {
			rec.mu.RLock()
			lc = len(rec.Logs)
			rec.mu.RUnlock()
		}
		out = append(out, jobSummary{PatchJob: j, LogCount: lc})
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{"jobs": out, "total": len(out)})
}

func (s *PatchServer) getJob(w http.ResponseWriter, r *http.Request, jobID string) {
	rec, ok := s.store.get(jobID)
	if !ok {
		jsonResponse(w, http.StatusNotFound, map[string]string{"error": "job not found"})
		return
	}
	job, logs, errMsg := rec.snapshot()

	// Also include audit events
	var auditEvents []*models.AuditEvent
	if rec.AuditWriter != nil {
		auditEvents = rec.AuditWriter.All()
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"job":    job,
		"logs":   logs,
		"error":  errMsg,
		"audit":  auditEvents,
	})
}

func (s *PatchServer) createJob(w http.ResponseWriter, r *http.Request) {
	var req CreateJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}

	// Validate required fields
	if req.Host == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "host is required"})
		return
	}
	if req.User == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "user is required"})
		return
	}
	if req.PrivateKeyPEM == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "private_key_pem is required"})
		return
	}
	if req.HostKeyFingerprint == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "host_key_fingerprint is required"})
		return
	}
	if req.Package == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "package is required"})
		return
	}
	if req.DryRun {
		jsonResponse(w, http.StatusBadRequest, map[string]string{
			"error": "dry_run mode is not supported via the API server. Use the CLI orchestrator binary with a dedicated test host.",
		})
		return
	}

	port := req.Port
	if port == 0 {
		port = 22
	}

	// Build unique job ID
	jobID := fmt.Sprintf("job_%d", time.Now().UnixNano())

	// Build domain objects
	job := &models.PatchJob{
		JobID:               jobID,
		IncidentID:          fmt.Sprintf("inc_%s", jobID),
		AssetID:             fmt.Sprintf("ast_%s", req.Host),
		State:               models.StateDetected,
		VulnerabilityStatus: models.VulnStatusPresent,
		CreatedAt:           time.Now().UTC(),
		UpdatedAt:           time.Now().UTC(),
	}

	asset := &models.TargetAsset{
		AssetID:  job.AssetID,
		Hostname: req.Host,
		Address:  req.Host,
		SSHConfig: models.SSHTarget{
			Port:               port,
			User:               req.User,
			HostKeyFingerprint: req.HostKeyFingerprint,
		},
		Criticality: models.CriticalityMedium,
	}

	restartServices := req.RestartServices
	plan := &models.RemediationPlan{
		PlanID:      fmt.Sprintf("plan_%s", jobID),
		Confidence:  models.ConfidenceHigh,
		Operations: []models.RemediationOperation{
			{
				Type:            models.OpPkgUpgrade,
				Package:         req.Package,
				TargetVersion:   req.TargetVersion,
				RestartServices: restartServices,
			},
		},
		SuccessCriteria: models.SuccessCriteria{
			MinPackageVersion: req.TargetVersion,
		},
	}

	// Build in-memory audit writer
	memAudit := audit.NewMemoryWriter()

	// Create record
	rec := &JobRecord{
		Job:         job,
		Logs:        make([]string, 0, 64),
		AuditWriter: memAudit,
	}
	rec.appendLog(fmt.Sprintf("Job %s created: upgrading %s on %s@%s:%d", jobID, req.Package, req.User, req.Host, port))
	s.store.set(rec)

	// Build SSH Manager
	sshCfg := ssh.Config{
		Host:               req.Host,
		Port:               port,
		User:               req.User,
		PrivateKeyPEM:      []byte(req.PrivateKeyPEM),
		HostKeyFingerprint: req.HostKeyFingerprint,
		ConnectTimeout:     15 * time.Second,
		CommandTimeout:     10 * time.Minute,
		MaxOutputBytes:     1024 * 1024,
	}

	sshMgr, err := ssh.NewManager(sshCfg)
	if err != nil {
		rec.mu.Lock()
		rec.Error = "SSH configuration error: " + err.Error()
		rec.mu.Unlock()
		rec.appendLog("[ERROR] " + err.Error())
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Build loggingRunner to intercept all ssh commands and mirror to rec.Logs
	runner := &loggingRunner{inner: sshMgr, rec: rec}

	// Wire up all engines
	pre := precheck.NewPrecheckEngine(runner)
	snap := snapshot.NewManager(runner)
	pat := patch.NewEngine(runner)
	val := validation.NewEngine(runner)
	rb := rollback.NewManager(runner)
	apr := approval.NewDefaultEvaluator(false)

	orch := orchestrator.NewOrchestrator(job, asset, plan, memAudit, pre, snap, pat, val, rb, apr)
	rec.mu.Lock()
	rec.Orch = orch
	rec.mu.Unlock()

	// Return immediately with job ID — run in background
	jsonResponse(w, http.StatusCreated, map[string]interface{}{
		"job_id":  jobID,
		"state":   job.State,
		"message": "Job accepted and running. Poll GET /api/v1/jobs/" + jobID + " for status and logs.",
	})

	go func() {
		defer sshMgr.Close()
		rec.appendLog("Establishing SSH connection to " + req.Host + "...")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		if err := orch.Run(ctx); err != nil {
			rec.mu.Lock()
			rec.Error = err.Error()
			rec.mu.Unlock()
			rec.appendLog("[ERROR] Pipeline terminated: " + err.Error())
			log.Printf("[job:%s] error: %v", jobID, err)
		} else {
			finalJob := orch.Job()
			rec.appendLog(fmt.Sprintf("[DONE] Final state: %s | Outcome: %v | Vulnerability: %s",
				finalJob.State,
				func() string {
					if finalJob.Outcome != nil {
						return string(*finalJob.Outcome)
					}
					return "PENDING"
				}(),
				finalJob.VulnerabilityStatus,
			))
			log.Printf("[job:%s] completed: state=%s", jobID, finalJob.State)
		}
	}()
}

func (s *PatchServer) triggerRollback(w http.ResponseWriter, r *http.Request, jobID string) {
	rec, ok := s.store.get(jobID)
	if !ok {
		jsonResponse(w, http.StatusNotFound, map[string]string{"error": "job not found"})
		return
	}

	rec.mu.RLock()
	orch := rec.Orch
	currentState := rec.Job.State
	rec.mu.RUnlock()

	if orch == nil {
		jsonResponse(w, http.StatusConflict, map[string]string{"error": "orchestrator not initialized for this job"})
		return
	}

	// Manual rollback is only meaningful if job ended in REMEDIATED (rollback a successful patch)
	// or in intermediate states that can accept rollback
	if currentState.IsTerminal() && currentState != models.StateRemediated {
		jsonResponse(w, http.StatusConflict, map[string]string{
			"error": fmt.Sprintf("job is in terminal state %s and cannot be rolled back", currentState),
		})
		return
	}

	rec.appendLog("[MANUAL ROLLBACK] Operator-initiated rollback requested.")
	jsonResponse(w, http.StatusAccepted, map[string]interface{}{
		"job_id":  jobID,
		"message": "Manual rollback is only available when the orchestrator is in a rollback-eligible state. The pipeline handles rollback automatically on failure.",
		"state":   currentState,
	})
}

// loggingRunner wraps the SSH Runner and mirrors all command refs to job logs.
type loggingRunner struct {
	inner ssh.Runner
	rec   *JobRecord
}

func (l *loggingRunner) Run(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
	l.rec.appendLog(fmt.Sprintf("→ %s", op.Ref))
	res, err := l.inner.Run(ctx, op)
	if err != nil {
		l.rec.appendLog(fmt.Sprintf("  [ERR] %s: %v", op.Ref, err))
	} else if res != nil && res.ExitCode != nil && *res.ExitCode != 0 {
		l.rec.appendLog(fmt.Sprintf("  [EXIT:%d] %s | stderr: %s", *res.ExitCode, op.Ref, truncate(res.Stderr, 120)))
	} else if res != nil && res.Stdout != "" {
		l.rec.appendLog(fmt.Sprintf("  ✓ %s: %s", op.Ref, truncate(res.Stdout, 100)))
	}
	return res, err
}

func (l *loggingRunner) Close() error {
	return l.inner.Close()
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// StartServer launches the HTTP API server.
func StartServer(port int, auditDir string) error {
	srv := NewPatchServer(auditDir)
	addr := fmt.Sprintf(":%d", port)
	log.Printf("[SSH Patch Orchestrator] HTTP API server listening on %s", addr)
	return http.ListenAndServe(addr, srv.Handler())
}
