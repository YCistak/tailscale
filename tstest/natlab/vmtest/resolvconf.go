// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"regexp"
	"sync"

	"tailscale.com/util/mak"
)

// Specifies where openresolv gets installed in the guest. openresolv's build
// is just a set of sed substitutions that bake these paths into its scripts
// (see its Makefile), so they have to agree with openresolvSubst below.
const (
	// openresolvSbinDir must be on the default PATH, because net/dns finds
	// resolvconf with exec.LookPath (see resolvconfStyle in
	// net/dns/resolvconf.go).
	openresolvSbinDir = "/sbin"

	// openresolvSysconfDir is where resolvconf looks for resolvconf.conf.
	openresolvSysconfDir = "/etc"

	// openresolvLibexecDir holds the subscriber scripts resolvconf runs after
	// a snippet is added or removed.
	openresolvLibexecDir = "/usr/libexec/resolvconf"

	// openresolvVarDir is resolvconf's runtime state directory. Its "keys"
	// subdirectory is where registered config snippets live.
	openresolvVarDir = "/run/resolvconf"

	// openresolvKeyDir is created empty by provisioning; see [DNSOpenresolv].
	openresolvKeyDir = openresolvVarDir + "/keys"
)

// openresolvStepName is the web-UI step for fetching and installing openresolv.
const openresolvStepName = "Prepare openresolv"

// openresolvFile is one file natlab installs into the guest to provide
// openresolv.
type openresolvFile struct {
	guestPath string           // absolute path to install to in the guest
	servePath string           // path the vnet fileserver serves it at
	asset     *ThirdPartyAsset // upstream source to substitute, if any
	inline    string           // literal contents, for files not fetched upstream
	exec      bool             // whether the guest must chmod +x it
}

// openresolvInstall is the subset of openresolv's own files this mode installs.
//
// Upstream ships further subscriber scripts (dnsmasq, unbound, avahi-daemon,
// and others), but both subscriber loops skip a script that isn't there. Only
// libc is needed, because it is the one that writes resolv.conf.
var openresolvInstall = []openresolvFile{
	{
		guestPath: openresolvSbinDir + "/resolvconf",
		servePath: "openresolv/resolvconf",
		asset:     &openresolvScript,
		exec:      true,
	},
	{
		// resolvconf sources this rather than exec'ing it if it isn't
		// executable, so it needs no exec bit.
		guestPath: openresolvLibexecDir + "/libc",
		servePath: "openresolv/libc",
		asset:     &openresolvLibc,
	},
	{
		// Upstream's own default, which its "make install" installs too.
		// What matters here is that the file exists at all: without it,
		// resolvconf switches to the original Debian layout if
		// /etc/resolvconf happens to be a directory, which is not what this
		// mode tests.
		guestPath: openresolvSysconfDir + "/resolvconf.conf",
		servePath: "openresolv/resolvconf.conf",
		inline:    "resolv_conf=/etc/resolv.conf\n",
	},
}

// openresolvSubst is openresolv's build-time substitution table. Its Makefile
// seds these placeholders out of the .in files; natlab does the same, so the
// test needs no configure-and-make step.
//
// RCDIR, RESTARTCMD and STATUSARG are empty, as they are in an unconfigured
// upstream build. resolvconf's detect_init() then picks a restart command at
// runtime, systemctl on these guests, and restarts the libc service only if it
// is already active. nscd is not.
var openresolvSubst = map[string]string{
	"@SBINDIR@":    openresolvSbinDir,
	"@SYSCONFDIR@": openresolvSysconfDir,
	"@LIBEXECDIR@": openresolvLibexecDir,
	"@VARDIR@":     openresolvVarDir,
	"@RCDIR@":      "",
	"@RESTARTCMD@": "",
	"@STATUSARG@":  "",
}

var openresolvPlaceholderRx = regexp.MustCompile(`@[A-Z_]+@`)

// substOpenresolv applies openresolvSubst to b, and fails if any placeholder
// survives. An openresolv release that adds one would otherwise install a
// shell script containing a literal "@FOO@", which fails in the guest in some
// far less obvious way.
func substOpenresolv(name string, b []byte) ([]byte, error) {
	for k, v := range openresolvSubst {
		b = bytes.ReplaceAll(b, []byte(k), []byte(v))
	}
	if m := openresolvPlaceholderRx.Find(b); m != nil {
		return nil, fmt.Errorf("%s: unsubstituted placeholder %q; openresolvSubst needs updating for openresolv %s", name, m, openresolvRef)
	}
	return b, nil
}

// buildOpenresolv returns the files to serve to the guest, keyed by their
// servePath. The caller must have ensured every asset is cached.
func buildOpenresolv() (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, f := range openresolvInstall {
		if f.asset == nil {
			out[f.servePath] = []byte(f.inline)
			continue
		}
		b, err := os.ReadFile(cachedAssetPath(*f.asset))
		if err != nil {
			return nil, err
		}
		if b, err = substOpenresolv(f.asset.Name, b); err != nil {
			return nil, err
		}
		out[f.servePath] = b
	}
	return out, nil
}

// ensureDNSModeAssets publishes the files a guest has to download in order to
// be provisioned for mode, so they are on the vnet fileserver before the VM
// boots and cloud-init fetches them. Most modes need nothing. Safe for
// concurrent use; does the work once per mode.
func (e *Env) ensureDNSModeAssets(ctx context.Context, mode DNSMode) error {
	if mode != DNSOpenresolv {
		return nil
	}

	e.compileMu.Lock()
	once, ok := e.dnsAssetOnce[mode]
	if !ok {
		once = new(sync.Once)
		mak.Set(&e.dnsAssetOnce, mode, once)
	}
	e.compileMu.Unlock()

	var err error
	once.Do(func() {
		step := e.Step(openresolvStepName)
		step.Begin()
		err = e.prepareOpenresolv(ctx)
		step.End(err)
	})
	return err
}

// prepareOpenresolv downloads openresolv's sources if needed, builds its guest
// files, and registers them with the vnet fileserver.
func (e *Env) prepareOpenresolv(ctx context.Context) error {
	for _, f := range openresolvInstall {
		if f.asset == nil {
			continue
		}
		if err := ensureAsset(ctx, *f.asset); err != nil {
			return err
		}
	}
	files, err := buildOpenresolv()
	if err != nil {
		return err
	}
	e.initVnet()
	for servePath, data := range files {
		e.server.RegisterFile(servePath, data)
	}
	return nil
}
