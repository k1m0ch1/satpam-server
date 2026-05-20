package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const githubRepo = "k1m0ch1/satpam-server"

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// fetchLatestRelease returns the latest GitHub release metadata.
func fetchLatestRelease(ctx context.Context) (*ghRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", githubRepo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}
	var rel ghRelease
	return &rel, json.NewDecoder(resp.Body).Decode(&rel)
}

func findAssetURL(rel *ghRelease) (string, error) {
	name := fmt.Sprintf("satpam-server-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	for _, a := range rel.Assets {
		if a.Name == name {
			return a.BrowserDownloadURL, nil
		}
	}
	return "", fmt.Errorf("no asset for %s/%s in release %s", runtime.GOOS, runtime.GOARCH, rel.TagName)
}

func applyUpdate(ctx context.Context, assetURL, newVersion string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("eval symlinks: %w", err)
	}

	slog.Info("downloading update", "version", newVersion, "url", assetURL)
	tmp := exe + ".new"
	if err := downloadBinary(ctx, assetURL, tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("download: %w", err)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("chmod: %w", err)
	}
	if err := replaceBinary(exe, tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace binary: %w", err)
	}

	slog.Info("update applied, relaunching", "version", newVersion, "exe", exe)
	return reexec(exe)
}

func downloadBinary(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func replaceBinary(exe, tmp string) error {
	if runtime.GOOS == "windows" {
		old := exe + ".old"
		_ = os.Remove(old)
		if err := os.Rename(exe, old); err != nil {
			return fmt.Errorf("rename current binary: %w", err)
		}
		if err := os.Rename(tmp, exe); err != nil {
			_ = os.Rename(old, exe)
			return fmt.Errorf("place new binary: %w", err)
		}
		return nil
	}
	return os.Rename(tmp, exe) // atomic on Unix
}

// ── semver helpers ────────────────────────────────────────────────────────────

func isNewer(latest, current string) bool {
	return semverCmp(latest, current) > 0
}

func semverCmp(a, b string) int {
	pa, pb := parseSemver(a), parseSemver(b)
	for i := range pa {
		if pa[i] > pb[i] {
			return 1
		}
		if pa[i] < pb[i] {
			return -1
		}
	}
	return 0
}

func parseSemver(v string) [3]int {
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 3)
	var out [3]int
	for i, p := range parts {
		if i >= 3 {
			break
		}
		out[i], _ = strconv.Atoi(p)
	}
	return out
}
