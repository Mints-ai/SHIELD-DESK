package security

import (
	"testing"
)

func TestValidatePackageName(t *testing.T) {
	valid := []string{
		"openssl",
		"libssl-dev",
		"nginx",
		"linux-image-5.15.0-89-generic",
		"curl",
		"pkg+extra:1",
	}
	for _, name := range valid {
		if err := ValidatePackageName(name); err != nil {
			t.Errorf("expected valid package name %q, got error: %v", name, err)
		}
	}

	invalid := []string{
		"",
		"pkg; rm -rf /",
		"pkg && evil",
		"$(whoami)",
		"`id`",
		"pkg|cat",
		"-pkg",
		"pkg>file",
		"pkg<file",
		"pkg\nexploit",
	}
	for _, name := range invalid {
		if err := ValidatePackageName(name); err == nil {
			t.Errorf("expected invalid package name %q to fail, but got nil", name)
		}
	}
}

func TestValidateServiceName(t *testing.T) {
	valid := []string{
		"nginx",
		"ssh",
		"systemd-journald",
		"docker.service",
		"user@1000.service",
	}
	for _, name := range valid {
		if err := ValidateServiceName(name); err != nil {
			t.Errorf("expected valid service name %q, got error: %v", name, err)
		}
	}

	invalid := []string{
		"",
		"service; reboot",
		"service && evil",
		"$(reboot)",
		"`reboot`",
		"service|ls",
	}
	for _, name := range invalid {
		if err := ValidateServiceName(name); err == nil {
			t.Errorf("expected invalid service name %q to fail, but got nil", name)
		}
	}
}

func TestValidateLVName(t *testing.T) {
	valid := []string{
		"root",
		"vg0",
		"data_lv",
		"sd_job_123_root",
	}
	for _, name := range valid {
		if err := ValidateLVName(name); err != nil {
			t.Errorf("expected valid LV name %q, got error: %v", name, err)
		}
	}

	invalid := []string{
		"",
		"vg0; lvremove -f",
		"vg0 && echo",
		"$HOME",
		"lv/invalid",
	}
	for _, name := range invalid {
		if err := ValidateLVName(name); err == nil {
			t.Errorf("expected invalid LV name %q to fail, but got nil", name)
		}
	}
}

func TestContainsShellMetacharacters(t *testing.T) {
	positives := []string{
		";", "&", "|", "$var", "`cmd`", "$(cmd)", "{a,b}", "<file", ">file", "!1",
		"a'b", "a\"b", "a\nb", "a\rb", "a\\b",
	}
	for _, s := range positives {
		if !ContainsShellMetacharacters(s) {
			t.Errorf("expected ContainsShellMetacharacters(%q) to be true", s)
		}
	}

	negatives := []string{
		"openssl",
		"1.1.1f-1ubuntu2.20",
		"libssl3",
		"ubuntu-22.04",
	}
	for _, s := range negatives {
		if ContainsShellMetacharacters(s) {
			t.Errorf("expected ContainsShellMetacharacters(%q) to be false", s)
		}
	}
}
