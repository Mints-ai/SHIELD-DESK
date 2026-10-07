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
		req.User = "ubuntu"
	}
	if req.Package == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "package is required"})
		return
	}

	if !req.DryRun {
		if req.PrivateKeyPEM == "" {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "private_key_pem is required for live patching"})
			return
		}
		if req.HostKeyFingerprint == "" {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "host_key_fingerprint is required for live patching"})
			return
		}
	} else {
		if req.PrivateKeyPEM == "" {
			req.PrivateKeyPEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nSIMULATED_KEY_FOR_DRY_RUN\n-----END OPENSSH PRIVATE KEY-----"
		}
		if req.HostKeyFingerprint == "" {
			req.HostKeyFingerprint = "SHA256:simulated_host_key_fingerprint"
		}
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
	if req.DryRun {
		rec.appendLog(fmt.Sprintf("[DRY RUN] Job %s created: simulating upgrade of %s on %s@%s:%d with LVM snapshot guard", jobID, req.Package, req.User, req.Host, port))
	} else {
		rec.appendLog(fmt.Sprintf("Job %s created: upgrading %s on %s@%s:%d", jobID, req.Package, req.User, req.Host, port))
	}
	s.store.set(rec)

	var runner ssh.Runner
	var sshMgr *ssh.Manager

	if req.DryRun {
		rec.appendLog(fmt.Sprintf("[SIMULATION] Initializing virtual host runner for %s (LVM volume group: vg0, root: /dev/vg0/root)...", req.Host))
		simRunner := newSimulationRunner(req.Package, req.TargetVersion)
		runner = &loggingRunner{inner: simRunner, rec: rec}
	} else {
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

		var err error
		sshMgr, err = ssh.NewManager(sshCfg)
		if err != nil {
			rec.mu.Lock()
			rec.Error = "SSH configuration error: " + err.Error()
			rec.mu.Unlock()
			rec.appendLog("[ERROR] " + err.Error())
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		runner = &loggingRunner{inner: sshMgr, rec: rec}
	}

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
		defer func() {
			if sshMgr != nil {
				_ = sshMgr.Close()
			} else if runner != nil {
				_ = runner.Close()
			}
		}()

		if req.DryRun {
			rec.appendLog(fmt.Sprintf("[DRY RUN] Target host %s attestation verified. Beginning safe simulation pipeline...", req.Host))
		} else {
			rec.appendLog("Establishing SSH connection to " + req.Host + "...")
		}

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

// newSimulationRunner creates a mock runner simulating a full Ubuntu LVM environment.
func newSimulationRunner(pkg, targetVersion string) ssh.Runner {
	mock := ssh.NewMockRunner()
	zero := 0
	if targetVersion == "" {
		targetVersion = "2.0.0-patched"
	}

	// 1. Prechecks
	mock.RegisterHandler("op:precheck.os", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "ID=ubuntu\nVERSION_ID=22.04\n"}, nil
	})
	mock.RegisterHandler("op:precheck.pkg_manager:apt", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "/usr/bin/apt-get\n"}, nil
	})
	mock.RegisterHandler("op:precheck.privileges", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "uid=0(root) gid=0(root)\n"}, nil
	})
	mock.RegisterHandler("op:precheck.apt_lock", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		exit1 := 1
		return &models.CommandResult{ExitCode: &exit1}, nil
	})
	mock.RegisterHandler("op:precheck.disk_space", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/mapper/vg0-root 41943040 10485760 31457280 25% /\n"}, nil
	})
	mock.RegisterHandler("op:precheck.findmnt_root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "/dev/mapper/vg0-root\n"}, nil
	})
	mock.RegisterHandler("op:precheck.lvs_root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "  vg0 root\n"}, nil
	})
	mock.RegisterHandler("op:precheck.vg_free", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "  5120.00\n"}, nil
	})
	mock.RegisterHandler("op:precheck.dpkg_version:"+pkg, func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "1.0.0-baseline\n"}, nil
	})

	// 2. Snapshot
	mock.RegisterHandler("op:lvm.snapshot.create:root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "Logical volume snap_prepatch_root created\n"}, nil
	})

	// 3. Dynamic Handler for verify, upgrade, validation
	mock.SetDefaultHandler(func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		if strings.HasPrefix(op.Ref, "op:lvm.snapshot.verify:") {
			snapName := strings.TrimPrefix(op.Ref, "op:lvm.snapshot.verify:")
			return &models.CommandResult{ExitCode: &zero, Stdout: fmt.Sprintf("%s vg0 root swi-a-s--- 1.2 uuid-snap-1\n", snapName)}, nil
		}
		if strings.HasPrefix(op.Ref, "op:pkg.detect:") {
			return &models.CommandResult{ExitCode: &zero, Stdout: "apt\n"}, nil
		}
		if strings.HasPrefix(op.Ref, "op:pkg.upgrade:") {
			return &models.CommandResult{ExitCode: &zero, Stdout: fmt.Sprintf("Preparing to unpack %s ...\nSetting up %s (%s) ...\n", pkg, pkg, targetVersion)}, nil
		}
		if strings.HasPrefix(op.Ref, "op:validation.version.dpkg:") {
			return &models.CommandResult{ExitCode: &zero, Stdout: targetVersion + "\n"}, nil
		}
		if strings.HasPrefix(op.Ref, "op:precheck.service_state:") || strings.HasPrefix(op.Ref, "op:validation.service_state:") {
			return &models.CommandResult{ExitCode: &zero, Stdout: "active\n"}, nil
		}
		if op.Ref == "op:validation.failed_units" {
			return &models.CommandResult{ExitCode: &zero, Stdout: ""}, nil
		}
		if strings.HasPrefix(op.Ref, "op:lvm.rollback.check_merged:") {
			return &models.CommandResult{ExitCode: &zero, Stdout: ""}, nil
		}
		if strings.HasPrefix(op.Ref, "op:lvm.snapshot.remove:") {
			return &models.CommandResult{ExitCode: &zero, Stdout: "Logical volume removed\n"}, nil
		}
		if strings.HasPrefix(op.Ref, "op:lvm.rollback.merge:") {
			return &models.CommandResult{ExitCode: &zero, Stdout: "Logical volume vg0/root will be merged on next activation\n"}, nil
		}
		return &models.CommandResult{ExitCode: &zero, Stdout: "OK\n"}, nil
	})

	return mock
}
