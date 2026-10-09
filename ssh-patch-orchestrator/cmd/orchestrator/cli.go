package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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

// RunCLI executes a one-shot patch job from command-line arguments.
func RunCLI(host string, port int, user, keyPath, hostKeyFP, pkg, targetVer, auditLog string) error {
	if host == "" {
		fmt.Println("ShieldDesk — SSH Patch Orchestrator with LVM Snapshot Rollback")
		fmt.Println("Usage: orchestrator run -host <ip> -key <path> -hostkey-fp <fp> -package <pkg> [-target-version <ver>]")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// 1. Setup SSH Manager
	sshCfg := ssh.Config{
		Host:               host,
		Port:               port,
		User:               user,
		PrivateKeyPath:     keyPath,
		HostKeyFingerprint: hostKeyFP,
		ConnectTimeout:     15 * time.Second,
		CommandTimeout:     10 * time.Minute,
		MaxOutputBytes:     1024 * 1024,
	}

	sshMgr, err := ssh.NewManager(sshCfg)
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}
	defer sshMgr.Close()

	// 2. Setup Audit Writer
	auditWriter, err := audit.NewJSONFileWriter(auditLog)
	if err != nil {
		return fmt.Errorf("failed to initialize audit logger: %w", err)
	}
	defer auditWriter.Close()

	// 3. Construct domain objects
	jobID := fmt.Sprintf("job_%d", time.Now().Unix())
	job := &models.PatchJob{
		JobID:               jobID,
		IncidentID:          fmt.Sprintf("inc_%s", jobID),
		AssetID:             fmt.Sprintf("ast_%s", host),
		State:               models.StateDetected,
		VulnerabilityStatus: models.VulnStatusPresent,
		CreatedAt:           time.Now().UTC(),
		UpdatedAt:           time.Now().UTC(),
	}

	asset := &models.TargetAsset{
		AssetID:  job.AssetID,
		Hostname: host,
		Address:  host,
		SSHConfig: models.SSHTarget{
			Port:               port,
			User:               user,
			HostKeyFingerprint: hostKeyFP,
		},
		Criticality: models.CriticalityMedium,
	}

	plan := &models.RemediationPlan{
		PlanID:     fmt.Sprintf("plan_%s", jobID),
		Confidence: models.ConfidenceHigh,
		Operations: []models.RemediationOperation{
			{
				Type:          models.OpPkgUpgrade,
				Package:       pkg,
				TargetVersion: targetVer,
			},
		},
		SuccessCriteria: models.SuccessCriteria{
			MinPackageVersion: targetVer,
		},
	}

	// 4. Initialize Engines
	pre := precheck.NewPrecheckEngine(sshMgr)
	snap := snapshot.NewManager(sshMgr)
	pat := patch.NewEngine(sshMgr)
	val := validation.NewEngine(sshMgr)
	rb := rollback.NewManager(sshMgr)
	apr := approval.NewDefaultEvaluator(false)

	orch := orchestrator.NewOrchestrator(job, asset, plan, auditWriter, pre, snap, pat, val, rb, apr)

	fmt.Printf("[+] Starting SSH Patch Orchestrator job: %s\n", jobID)
	fmt.Printf("[+] Target: %s@%s:%d (Strict Host Key: %s)\n", user, host, port, hostKeyFP)
	fmt.Printf("[+] Remediation: upgrade %s -> %s\n", pkg, targetVer)

	runErr := orch.Run(ctx)
	finalJob := orch.Job()

	fmt.Println()
	fmt.Println("================ Execution Summary ================")
	fmt.Printf("Final State:          %s\n", finalJob.State)
	if finalJob.Outcome != nil {
		fmt.Printf("Reported Outcome:     %s\n", *finalJob.Outcome)
	}
	fmt.Printf("Vulnerability Status: %s\n", finalJob.VulnerabilityStatus)
	fmt.Printf("Audit Log:            %s\n", auditLog)

	if runErr != nil {
		fmt.Fprintf(os.Stderr, "Pipeline terminated with error: %v\n", runErr)
		if finalJob.State == models.StateEscalatedUrgent {
			os.Exit(2)
		}
		os.Exit(1)
	}

	statusJSON, _ := json.MarshalIndent(finalJob, "", "  ")
	fmt.Println(string(statusJSON))
	return nil
}
