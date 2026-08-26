// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ulikunitz/xz"
)

// LinuxFamily classifies a Linux distro by the conventions that affect how we
// provision it via cloud-init (default network manager, MAC/LSM, etc). It is
// only meaningful for Linux cloud images, which must declare one; the zero
// value means "undeclared".
type LinuxFamily string

const (
	// LinuxDebian covers Debian and Ubuntu cloud images: systemd-networkd for
	// networking and AppArmor as the LSM.
	LinuxDebian LinuxFamily = "debian"

	// LinuxRHEL covers Fedora, CentOS Stream, Rocky, and AlmaLinux cloud
	// images: NetworkManager + systemd-resolved for networking and SELinux
	// enforcing.
	LinuxRHEL LinuxFamily = "rhel"
)

// OSImage describes a VM operating system image.
type OSImage struct {
	Name      string
	URL       string      // download URL for the cloud image
	SHA256    string      // expected SHA256 hash of the image (of the final qcow2, after any decompression)
	MemoryMB  int         // RAM for the VM
	Family    LinuxFamily // Linux distro family (affects cloud-init user-data); empty means Debian-like
	IsGokrazy bool        // true for gokrazy images (different QEMU setup)
	IsMacOS   bool        // true for macOS images (launched via tailmac, not QEMU)
}

// GOOS returns the Go OS name for this image.
func (img OSImage) GOOS() string {
	if img.IsMacOS {
		return "darwin"
	}
	if img.IsGokrazy {
		return "linux"
	}
	if strings.HasPrefix(img.Name, "freebsd") {
		return "freebsd"
	}
	return "linux"
}

// GOARCH returns the Go architecture name for this image.
func (img OSImage) GOARCH() string {
	if img.IsMacOS {
		return "arm64"
	}
	return "amd64"
}

// isLinuxCloudImage reports whether the image is a Linux distro cloud image
// (Ubuntu, Debian, Fedora, ...), as opposed to gokrazy or a non-Linux OS.
// These are the images provisioned via generateLinuxUserData and are the ones
// that must declare a LinuxFamily.
func (img OSImage) isLinuxCloudImage() bool {
	return img.GOOS() == "linux" && !img.IsGokrazy
}

var (
	// Gokrazy is a minimal Tailscale appliance image built from the gokrazy/natlabapp directory.
	Gokrazy = OSImage{
		Name:      "gokrazy",
		IsGokrazy: true,
		MemoryMB:  384,
	}

	// Ubuntu2404 is Ubuntu 24.04 LTS (Noble Numbat) cloud image.
	Ubuntu2404 = OSImage{
		Name:     "ubuntu-24.04",
		URL:      "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img",
		MemoryMB: 1024,
		Family:   LinuxDebian,
	}

	// Debian12 is Debian 12 (Bookworm) generic cloud image.
	Debian12 = OSImage{
		Name:     "debian-12",
		URL:      "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2",
		MemoryMB: 1024,
		Family:   LinuxDebian,
	}

	// FreeBSD150 is FreeBSD 15.0-RELEASE with BASIC-CLOUDINIT (nuageinit) support.
	// The image is distributed as xz-compressed qcow2.
	FreeBSD150 = OSImage{
		Name:     "freebsd-15.0",
		URL:      "https://download.freebsd.org/releases/VM-IMAGES/15.0-RELEASE/amd64/Latest/FreeBSD-15.0-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz",
		MemoryMB: 1024,
	}

	// Fedora43 is the Fedora 43 Cloud Base image: NetworkManager +
	// systemd-resolved, SELinux enforcing, hence LinuxRHEL.
	Fedora43 = OSImage{
		Name:     "fedora-43",
		URL:      "https://download.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2",
		MemoryMB: 1024,
		Family:   LinuxRHEL,
	}

	// MacOS is a macOS VM launched via tailmac (Apple Virtualization.framework).
	// Uses a Tart pre-built base image (ghcr.io/cirruslabs/macos-tahoe-base)
	// which is automatically pulled on first use. Only runs on macOS arm64 hosts.
	MacOS = OSImage{
		Name:     "macos",
		IsMacOS:  true,
		MemoryMB: 4096,
	}
)

// ThirdPartyAsset is a pinned upstream file that natlab installs into a guest.
// It covers software that no cloud image ships and that the guest cannot fetch
// for itself, because vnet has no route to the real internet. natlab downloads
// it on the host into the vmtest cache and serves it to the guest over vnet's
// fileserver.
type ThirdPartyAsset struct {
	Name   string // cache filename, extension included
	URL    string
	SHA256 string // expected hash of the file as served, before any decompression
}

// openresolvRef pins the openresolv revision natlab installs, as a commit
// rather than the v3.17.4 tag it carries: a tag can be moved, a commit cannot.
// The files below are byte-identical to the same-named members of the v3.17.4
// release tarball.
const openresolvRef = "6489889ce5631364ad2f17d391e1a3ad969619f2" // v3.17.4

// openresolv is upstream openresolv, the resolvconf implementation behind
// net/dns's "openresolv" backend. Its build is a handful of sed substitutions
// over these two POSIX shell scripts rather than a compile, so natlab fetches
// them and substitutes in-process instead of installing a package. See
// resolvconf.go.
var (
	// openresolvScript is the resolvconf(8) program itself.
	openresolvScript = openresolvAsset("resolvconf.in",
		"c806bd4aa0d1c59736beae3af8a7e4c7cfd6a24664cfbc01be10b28af89f5b8c")

	// openresolvLibc is the subscriber that writes /etc/resolv.conf.
	openresolvLibc = openresolvAsset("libc.in",
		"25b7ba247cb033130035a09751d78be40786ee449a93f31c61b93409dabd54ea")
)

// openresolvAsset describes the openresolv source file named member, at
// openresolvRef. The URL and the cache name both derive from that ref, so a
// version bump means changing one constant and the hashes.
func openresolvAsset(member, sha256 string) ThirdPartyAsset {
	return ThirdPartyAsset{
		Name:   "openresolv-" + openresolvRef[:12] + "-" + member,
		URL:    "https://raw.githubusercontent.com/NetworkConfiguration/openresolv/" + openresolvRef + "/" + member,
		SHA256: sha256,
	}
}

// CloudImages returns the set of QEMU-bootable cloud OS images natlab can
// use for vmtests, excluding gokrazy (built from source) and macOS (which
// uses a separate snapshot pipeline). It is intended for tooling such as
// a CI prep step that wants to warm the image cache.
func CloudImages() []OSImage {
	return []OSImage{Ubuntu2404, Debian12, FreeBSD150, Fedora43}
}

// ThirdPartyAssets returns every [ThirdPartyAsset] natlab vmtests can install
// into a guest, for the same cache-warming tooling as [CloudImages].
func ThirdPartyAssets() []ThirdPartyAsset {
	return []ThirdPartyAsset{openresolvScript, openresolvLibc}
}

// EnsureImage downloads img to the local cache if not already present.
// It is intended for tooling that wants to warm the image cache before
// running natlab vmtests (e.g. a CI prep step). The test framework also
// calls into the package-internal equivalent on demand.
func EnsureImage(ctx context.Context, img OSImage) error {
	return ensureImage(ctx, img)
}

// EnsureAsset downloads asset to the local cache if not already present, for
// the same cache-warming tooling as [EnsureImage].
func EnsureAsset(ctx context.Context, asset ThirdPartyAsset) error {
	return ensureAsset(ctx, asset)
}

// imageCacheDir returns the directory for cached VM images.
func imageCacheDir() string {
	return cacheDir("images")
}

// assetCacheDir returns the directory for cached [ThirdPartyAsset] downloads.
// Assets keep their own filenames, unlike images, which are cached as .qcow2.
func assetCacheDir() string {
	return cacheDir("assets")
}

func cacheDir(kind string) string {
	if d := os.Getenv("VMTEST_CACHE_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cache", "tailscale", "vmtest", kind)
}

// ensureImage downloads and caches the OS image if not already present.
func ensureImage(ctx context.Context, img OSImage) error {
	if img.IsGokrazy {
		return nil // gokrazy images are handled separately
	}
	// Images are cached as bare qcow2, so an xz-compressed download is
	// decompressed on the way in and img.SHA256 covers the qcow2.
	return ensureCached(ctx, img.Name, img.URL, cachedImagePath(img), img.SHA256, strings.HasSuffix(img.URL, ".xz"))
}

// ensureAsset downloads and caches asset if not already present.
func ensureAsset(ctx context.Context, asset ThirdPartyAsset) error {
	// Assets are cached as downloaded: they're files we read in-process (see
	// resolvconf.go), not disk images QEMU has to open.
	return ensureCached(ctx, asset.Name, asset.URL, cachedAssetPath(asset), asset.SHA256, false)
}

// ensureCached downloads url to cachedPath unless a file with the wanted hash
// is already there. name is for logs and errors only. If decompressXZ, the
// download is xz-decompressed on the way to disk, so wantSHA256 (when
// non-empty) covers the decompressed bytes.
//
// The download lands in a temporary file and is renamed into place only after
// the hash checks out, so cachedPath is never a truncated or corrupt file.
func ensureCached(ctx context.Context, name, url, cachedPath, wantSHA256 string, decompressXZ bool) error {
	if err := os.MkdirAll(filepath.Dir(cachedPath), 0755); err != nil {
		return err
	}

	if _, err := os.Stat(cachedPath); err == nil {
		if wantSHA256 == "" {
			return nil // exists, no hash to verify
		}
		if err := verifySHA256(cachedPath, wantSHA256); err != nil {
			log.Printf("cached %s failed SHA256 check, re-downloading: %v", name, err)
			os.Remove(cachedPath)
		} else {
			return nil
		}
	}

	log.Printf("downloading %s from %s...", name, url)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", name, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("downloading %s: HTTP %s", name, resp.Status)
	}

	// Set up the reader pipeline: HTTP body → (optional xz decompress) → file.
	var src io.Reader = resp.Body
	if decompressXZ {
		xzr, err := xz.NewReader(resp.Body)
		if err != nil {
			return fmt.Errorf("creating xz reader for %s: %w", name, err)
		}
		src = xzr
	}

	tmpFile := cachedPath + ".tmp"
	f, err := os.Create(tmpFile)
	if err != nil {
		return err
	}
	defer func() {
		f.Close()
		os.Remove(tmpFile)
	}()

	h := sha256.New()
	w := io.MultiWriter(f, h)
	if _, err := io.Copy(w, src); err != nil {
		return fmt.Errorf("downloading %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return err
	}

	if wantSHA256 != "" {
		got := hex.EncodeToString(h.Sum(nil))
		if got != wantSHA256 {
			return fmt.Errorf("SHA256 mismatch for %s: got %s, want %s", name, got, wantSHA256)
		}
	}

	if err := os.Rename(tmpFile, cachedPath); err != nil {
		return err
	}
	log.Printf("downloaded %s", name)
	return nil
}

// verifySHA256 checks that the file at path has the expected SHA256 hash.
func verifySHA256(path, expected string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != expected {
		return fmt.Errorf("got %s, want %s", got, expected)
	}
	return nil
}

// cachedImagePath returns the filesystem path to the cached image for the given OS.
func cachedImagePath(img OSImage) string {
	return filepath.Join(imageCacheDir(), img.Name+".qcow2")
}

// cachedAssetPath returns the filesystem path to the cached download of asset.
func cachedAssetPath(asset ThirdPartyAsset) string {
	return filepath.Join(assetCacheDir(), asset.Name)
}

// createOverlay creates a qcow2 overlay image on top of the given base image.
func createOverlay(base, overlay string) error {
	out, err := exec.Command("qemu-img", "create",
		"-f", "qcow2",
		"-F", "qcow2",
		"-b", base,
		overlay).CombinedOutput()
	if err != nil {
		return fmt.Errorf("qemu-img create overlay: %v: %s", err, out)
	}
	return nil
}
