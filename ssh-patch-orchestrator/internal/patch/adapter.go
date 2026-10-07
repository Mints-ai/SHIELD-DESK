package patch

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/security"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/ssh"
)

// PackageManager abstracts OS package management actions behind safe argument vectors.
type PackageManager interface {
	Name() string
	Detect(ctx context.Context, r ssh.Runner) (bool, error)
	InstalledVersion(ctx context.Context, r ssh.Runner, pkg string) (string, error)
	Upgrade(ctx context.Context, r ssh.Runner, pkg, targetVersion string) (*models.CommandResult, error)
	Install(ctx context.Context, r ssh.Runner, pkg, targetVersion string) (*models.CommandResult, error)
	IsLocked(ctx context.Context, r ssh.Runner) (bool, error)
}

// AptAdapter implements PackageManager for Debian and Ubuntu distributions.
type AptAdapter struct{}

func NewAptAdapter() *AptAdapter {
	return &AptAdapter{}
}

func (a *AptAdapter) Name() string {
	return "apt"
}

func (a *AptAdapter) Detect(ctx context.Context, r ssh.Runner) (bool, error) {
	res, err := r.Run(ctx, models.Operation{
		Ref:  "op:pkg.detect:apt",
		ArgV: []string{"which", "apt-get"},
	})
	if err == nil && res.ExitCode != nil && *res.ExitCode == 0 {
		return true, nil
	}
	return false, nil
}

func (a *AptAdapter) InstalledVersion(ctx context.Context, r ssh.Runner, pkg string) (string, error) {
	if err := security.ValidatePackageName(pkg); err != nil {
		return "", err
	}
	res, err := r.Run(ctx, models.Operation{
		Ref:  fmt.Sprintf("op:pkg.version.dpkg:%s", pkg),
		ArgV: []string{"dpkg-query", "-W", "-f=${Version}", pkg},
	})
	if err != nil || res.ExitCode == nil || *res.ExitCode != 0 {
		return "", fmt.Errorf("failed querying dpkg version for %s: %v", pkg, err)
	}
	return strings.TrimSpace(res.Stdout), nil
}

func (a *AptAdapter) Upgrade(ctx context.Context, r ssh.Runner, pkg, targetVersion string) (*models.CommandResult, error) {
	if err := security.ValidatePackageName(pkg); err != nil {
		return nil, err
	}

	argv := []string{
		"sudo", "env", "DEBIAN_FRONTEND=noninteractive",
		"apt-get", "install", "--only-upgrade", "-y",
	}

	if targetVersion != "" {
		if err := security.ValidateVersion(targetVersion); err != nil {
			return nil, err
		}
		argv = append(argv, fmt.Sprintf("%s=%s", pkg, targetVersion))
	} else {
		argv = append(argv, pkg)
	}

	return r.Run(ctx, models.Operation{
		Ref:     fmt.Sprintf("op:pkg.upgrade:apt:%s", pkg),
		ArgV:    argv,
		Timeout: 10 * time.Minute,
	})
}

func (a *AptAdapter) Install(ctx context.Context, r ssh.Runner, pkg, targetVersion string) (*models.CommandResult, error) {
	if err := security.ValidatePackageName(pkg); err != nil {
		return nil, err
	}

	argv := []string{
		"sudo", "env", "DEBIAN_FRONTEND=noninteractive",
		"apt-get", "install", "-y",
	}

	if targetVersion != "" {
		if err := security.ValidateVersion(targetVersion); err != nil {
			return nil, err
		}
		argv = append(argv, fmt.Sprintf("%s=%s", pkg, targetVersion))
	} else {
		argv = append(argv, pkg)
	}

	return r.Run(ctx, models.Operation{
		Ref:     fmt.Sprintf("op:pkg.install:apt:%s", pkg),
		ArgV:    argv,
		Timeout: 10 * time.Minute,
	})
}

func (a *AptAdapter) IsLocked(ctx context.Context, r ssh.Runner) (bool, error) {
	res, err := r.Run(ctx, models.Operation{
		Ref:  "op:pkg.lock:apt",
		ArgV: []string{"fuser", "/var/lib/dpkg/lock-frontend"},
	})
	if err == nil && res.ExitCode != nil && *res.ExitCode == 0 {
		return true, nil
	}
	return false, nil
}

// DnfAdapter implements PackageManager for RHEL, CentOS, Rocky, and AlmaLinux.
type DnfAdapter struct{}

func NewDnfAdapter() *DnfAdapter {
	return &DnfAdapter{}
}

func (d *DnfAdapter) Name() string {
	return "dnf"
}

func (d *DnfAdapter) Detect(ctx context.Context, r ssh.Runner) (bool, error) {
	res, err := r.Run(ctx, models.Operation{
		Ref:  "op:pkg.detect:dnf",
		ArgV: []string{"which", "dnf"},
	})
	if err == nil && res.ExitCode != nil && *res.ExitCode == 0 {
		return true, nil
	}
	return false, nil
}

func (d *DnfAdapter) InstalledVersion(ctx context.Context, r ssh.Runner, pkg string) (string, error) {
	if err := security.ValidatePackageName(pkg); err != nil {
		return "", err
	}
	res, err := r.Run(ctx, models.Operation{
		Ref:  fmt.Sprintf("op:pkg.version.rpm:%s", pkg),
		ArgV: []string{"rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", pkg},
	})
	if err != nil || res.ExitCode == nil || *res.ExitCode != 0 {
		return "", fmt.Errorf("failed querying rpm version for %s: %v", pkg, err)
	}
	return strings.TrimSpace(res.Stdout), nil
}

func (d *DnfAdapter) Upgrade(ctx context.Context, r ssh.Runner, pkg, targetVersion string) (*models.CommandResult, error) {
	if err := security.ValidatePackageName(pkg); err != nil {
		return nil, err
	}
	target := pkg
	if targetVersion != "" {
		if err := security.ValidateVersion(targetVersion); err != nil {
			return nil, err
		}
		target = fmt.Sprintf("%s-%s", pkg, targetVersion)
	}
	return r.Run(ctx, models.Operation{
		Ref:     fmt.Sprintf("op:pkg.upgrade:dnf:%s", pkg),
		ArgV:    []string{"sudo", "dnf", "upgrade", "-y", target},
		Timeout: 10 * time.Minute,
	})
}

func (d *DnfAdapter) Install(ctx context.Context, r ssh.Runner, pkg, targetVersion string) (*models.CommandResult, error) {
	if err := security.ValidatePackageName(pkg); err != nil {
		return nil, err
	}
	target := pkg
	if targetVersion != "" {
		if err := security.ValidateVersion(targetVersion); err != nil {
			return nil, err
		}
		target = fmt.Sprintf("%s-%s", pkg, targetVersion)
	}
	return r.Run(ctx, models.Operation{
		Ref:     fmt.Sprintf("op:pkg.install:dnf:%s", pkg),
		ArgV:    []string{"sudo", "dnf", "install", "-y", target},
		Timeout: 10 * time.Minute,
	})
}

func (d *DnfAdapter) IsLocked(ctx context.Context, r ssh.Runner) (bool, error) {
	return false, nil
}
