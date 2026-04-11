package airplay

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveALACCaptureModeDefaultsToVerbatimWithoutHelper(t *testing.T) {
	t.Setenv("ALAC_ENCODER", "")
	t.Setenv("PATH", t.TempDir())
	t.Chdir(t.TempDir())

	mode, helper, err := resolveALACCaptureMode()
	if err != nil {
		t.Fatalf("resolveALACCaptureMode returned error: %v", err)
	}
	if mode != alacCaptureVerbatim {
		t.Fatalf("mode = %v, want verbatim fallback", mode)
	}
	if helper != "" {
		t.Fatalf("helper path = %q, want empty", helper)
	}
}

func TestResolveALACCaptureModePrefersHelperWhenAvailable(t *testing.T) {
	t.Setenv("ALAC_ENCODER", "")
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	t.Chdir(dir)
	helper := filepath.Join(dir, "alac-enc")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write helper: %v", err)
	}

	mode, gotHelper, err := resolveALACCaptureMode()
	if err != nil {
		t.Fatalf("resolveALACCaptureMode returned error: %v", err)
	}
	if mode != alacCaptureHelper {
		t.Fatalf("mode = %v, want helper", mode)
	}
	wantHelper := filepath.Join(".", "alac-enc")
	if gotHelper != wantHelper {
		t.Fatalf("helper path = %q, want %q", gotHelper, wantHelper)
	}
}

func TestResolveALACCaptureModeExplicitHelperRequiresBinary(t *testing.T) {
	t.Setenv("ALAC_ENCODER", "helper")
	t.Setenv("PATH", t.TempDir())
	t.Chdir(t.TempDir())

	if _, _, err := resolveALACCaptureMode(); err == nil {
		t.Fatal("expected missing helper to return an error")
	}
}
