// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"context"
	"strings"
	"testing"
)

// TestBuildOpenresolv checks that the pinned openresolv sources still build
// into what the guest expects. It is the cheap half of the openresolv
// coverage: an upstream bump that adds a build placeholder fails here in
// seconds, rather than as a puzzling DNS failure inside a VM several minutes
// into TestOpenresolvDNS.
//
// It needs the pinned sources, so it downloads on a cold cache and is skipped
// in short mode.
func TestBuildOpenresolv(t *testing.T) {
	if testing.Short() {
		t.Skip("downloads the openresolv sources; skipping in short mode")
	}
	for _, f := range openresolvInstall {
		if f.asset == nil {
			continue
		}
		if err := ensureAsset(context.Background(), *f.asset); err != nil {
			t.Fatalf("ensureAsset(%s): %v", f.asset.Name, err)
		}
	}

	// buildOpenresolv itself fails on a surviving @NAME@ placeholder, so
	// reaching here already covers that.
	files, err := buildOpenresolv()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(openresolvInstall) {
		t.Fatalf("built %d files, want %d", len(files), len(openresolvInstall))
	}

	for _, f := range openresolvInstall {
		data, ok := files[f.servePath]
		if !ok {
			t.Errorf("%s: not built", f.servePath)
			continue
		}
		if len(data) == 0 {
			t.Errorf("%s: empty", f.servePath)
		}
		if f.asset != nil && !strings.HasPrefix(string(data), "#!/bin/sh") {
			t.Errorf("%s: does not start with a /bin/sh shebang", f.servePath)
		}
	}

	// The substitutions have to have actually happened: resolvconf derives its
	// key directory from VARDIR, and net/dns's whole openresolv path hinges on
	// that directory being the one the test provisions.
	rc := string(files["openresolv/resolvconf"])
	for _, want := range []string{
		"VARDIR=" + openresolvVarDir,
		"LIBEXECDIR=" + openresolvLibexecDir,
		`KEYDIR="$VARDIR/keys"`,
	} {
		if !strings.Contains(rc, want) {
			t.Errorf("built resolvconf does not contain %q", want)
		}
	}
}
