package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	// --- Server mode (default when running as part of ShieldDesk) ---
	serverCmd := flag.NewFlagSet("server", flag.ExitOnError)
	serverPort := serverCmd.Int("port", 8004, "HTTP API server port")
	serverAuditDir := serverCmd.String("audit-dir", ".", "Directory for audit log files")

	// --- CLI mode (direct one-shot patch job) ---
	cliCmd := flag.NewFlagSet("run", flag.ExitOnError)
	cliHost := cliCmd.String("host", "", "Target Linux server hostname or IP")
	cliPort := cliCmd.Int("port", 22, "SSH port")
	cliUser := cliCmd.String("user", "shielddesk-patch", "SSH username")
	cliKeyPath := cliCmd.String("key", "", "Path to SSH private key")
	cliHostKeyFP := cliCmd.String("hostkey-fp", "", "Expected SHA256 host key fingerprint (e.g. SHA256:...)")
	cliPackage := cliCmd.String("package", "", "Package name to upgrade (e.g. openssl)")
	cliTargetVer := cliCmd.String("target-version", "", "Target package version (e.g. 1.1.1f-1ubuntu2.20)")
	cliAuditLog := cliCmd.String("audit-log", "audit.jsonl", "Path to audit log file")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "server":
		if err := serverCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if err := StartServer(*serverPort, *serverAuditDir); err != nil {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			os.Exit(1)
		}

	case "run":
		if err := cliCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if err := RunCLI(*cliHost, *cliPort, *cliUser, *cliKeyPath, *cliHostKeyFP, *cliPackage, *cliTargetVer, *cliAuditLog); err != nil {
			fmt.Fprintf(os.Stderr, "Run error: %v\n", err)
			os.Exit(1)
		}

	case "version", "-version", "--version":
		fmt.Println("ShieldDesk SSH Patch Orchestrator v1.0.0 (Go Implementation)")

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("ShieldDesk — SSH Patch Orchestrator with LVM Snapshot Rollback")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  orchestrator server [--port 8004] [--audit-dir .]")
	fmt.Println("      Start the HTTP API server (used by the ShieldDesk UI)")
	fmt.Println()
	fmt.Println("  orchestrator run -host <ip> -user <user> -key <path>")
	fmt.Println("                   -hostkey-fp <SHA256:...> -package <pkg>")
	fmt.Println("                   [-target-version <ver>] [-audit-log audit.jsonl]")
	fmt.Println("      Run a one-shot patch job from the command line")
	fmt.Println()
	fmt.Println("  orchestrator version")
	fmt.Println("      Print version information")
}
