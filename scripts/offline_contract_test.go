package scripts

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The offline bundle's promise is one sentence: after the tar.gz is on the
// server, nothing needs the network. That promise is not testable by running
// the installer here — it installs a panel — but the ways it has broken in
// other projects are all textual: a wrapper that quietly keeps a default
// download URL, an apt call that consults the system's real sources, a
// workflow that builds one release's packages inside another release's
// container. These tests pin the offline path the same way
// installer_contract_test.go pins the online one.

func readOfflineScript(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("offline", name))
	if err != nil {
		t.Fatalf("reading offline/%s: %v", name, err)
	}
	return strings.ReplaceAll(string(body), "\r\n", "\n")
}

// TestTheWrapperPinsTheInstallerToTheBundle is the core invariant: every
// delegation to install.sh names the bundle's own release directory. One
// call without --release-base would fall through to install.sh's default,
// which is a hostname — and the "offline" installer would be downloading.
func TestTheWrapperPinsTheInstallerToTheBundle(t *testing.T) {
	script := readOfflineScript(t, "install_offline.sh")

	if !strings.Contains(script, `RELEASE_BASE="$BUNDLE_ROOT/dist/release"`) {
		t.Error("RELEASE_BASE is not the bundle's own directory, so the delegated installer " +
			"could fetch from its default URL")
	}
	if !strings.Contains(script, `--release-base "$RELEASE_BASE" --version "$BUNDLE_VERSION"`) {
		t.Error("the delegation does not pin both --release-base and --version; install.sh " +
			"would resolve 'latest' against a host that is not there")
	}

	// Exactly one place runs install.sh, so the pin above covers every mode.
	calls := regexp.MustCompile(`(?m)bash "\$DELEGATE"`).FindAllString(script, -1)
	if len(calls) != 1 {
		t.Errorf("install.sh is invoked from %d places; a second call site is a second chance "+
			"to forget the --release-base pin", len(calls))
	}

	// And the flags that could redirect it are refused, not forwarded.
	if !strings.Contains(script, `--version|--release-base|--arch|--installer-url)`) {
		t.Error("the wrapper no longer refuses --release-base and --version overrides; one flag " +
			"would turn an offline installation into a download")
	}
}

// TestTheWrapperRunsNoDownloader: the wrapper itself must not contain a
// single network fetch. Comment lines are stripped first, for the same
// reason installer_contract_test.go strips them: prose warning about curl
// is not an invocation of curl.
func TestTheWrapperRunsNoDownloader(t *testing.T) {
	script := readOfflineScript(t, "install_offline.sh")
	var kept []string
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		// `command -v curl` asks whether a tool exists; it does not run it.
		// The wrapper legitimately asks, because a missing downloader is what
		// it installs a package for.
		if strings.Contains(line, "command -v") {
			continue
		}
		kept = append(kept, line)
	}
	body := strings.Join(kept, "\n")

	for _, fragment := range []string{"curl ", "wget ", "git clone", "docker pull",
		"snap install", "add-apt-repository", "http://", "https://"} {
		if strings.Contains(body, fragment) {
			t.Errorf("install_offline.sh contains %q outside a comment; the offline path must "+
				"not fetch anything", fragment)
		}
	}
}

// TestAptIsConfinedToTheBundleRepository: every apt-get the wrapper runs
// goes through one function that overrides apt's source configuration, so
// the system's real sources — and the mirrors behind them — cannot be
// consulted even by accident.
func TestAptIsConfinedToTheBundleRepository(t *testing.T) {
	script := readOfflineScript(t, "install_offline.sh")

	for _, needed := range []string{
		`-o Dir::Etc::sourcelist="$APT_STATE/offline.list"`,
		`-o Dir::Etc::sourceparts="$APT_STATE/parts"`,
		`-o Dir::State::lists="$APT_STATE/lists"`,
	} {
		if !strings.Contains(script, needed) {
			t.Errorf("the confined apt function no longer carries %s, so apt would read the "+
				"system's real sources", needed)
		}
	}

	// The confinement only confines if it is the only way apt is called.
	// "command -v apt-get" is a presence test, not an invocation.
	stripped := withoutComments(script)
	for i, line := range strings.Split(stripped, "\n") {
		if !strings.Contains(line, "apt-get") {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "command -v apt-get") {
			continue
		}
		if strings.Contains(trimmed, "DEBIAN_FRONTEND=noninteractive apt-get \\") {
			continue // the confined function's own body
		}
		t.Errorf("line %d calls apt-get outside the confined function: %s", i+1, trimmed)
	}

	if !strings.Contains(script, "offline_apt update") || !strings.Contains(script, "offline_apt install") {
		t.Error("packages are no longer installed through the confined apt function")
	}
}

// TestTheBundleIsVerifiedBeforeAnythingRuns: the SHA-256 check has to come
// before the menu, before packages, before delegation — running scripts as
// root out of an unverified archive is the thing the manifest exists to
// prevent. Order is checked by position, the way the online installer's
// tests check that the environment file is written before the service
// starts.
func TestTheBundleIsVerifiedBeforeAnythingRuns(t *testing.T) {
	script := readOfflineScript(t, "install_offline.sh")

	verify := strings.Index(script, "sha256sum --check --quiet checksums.sha256")
	if verify < 0 {
		t.Fatal("the wrapper never verifies checksums.sha256 at all")
	}
	for _, later := range []string{"ensure_packages", `bash "$DELEGATE"`, "read -r -p \"Choice: \""} {
		at := strings.Index(script, later)
		if at < 0 {
			t.Fatalf("could not find %q to compare order against", later)
		}
		if at < verify {
			t.Errorf("%q happens at byte %d, before the checksum verification at byte %d", later, at, verify)
		}
	}
}

// TestTheOfflineExitCodesAreDistinctAndDocumented mirrors the online
// installer's exit-code contract: a code the usage text promises has to
// exist, and no two constants may share a value.
func TestTheOfflineExitCodesAreDistinctAndDocumented(t *testing.T) {
	script := readOfflineScript(t, "install_offline.sh")

	declared := map[int]string{}
	for _, match := range regexp.MustCompile(`(?m)^readonly (EXIT_[A-Z_]+)=(\d+)`).
		FindAllStringSubmatch(script, -1) {
		code, err := strconv.Atoi(match[2])
		if err != nil {
			t.Fatalf("exit constant %s has a non-numeric value %q", match[1], match[2])
		}
		if existing, clash := declared[code]; clash {
			t.Errorf("%s and %s are both %d", existing, match[1], code)
		}
		declared[code] = match[1]
	}
	for _, code := range []int{19, 20, 21} {
		if _, ok := declared[code]; !ok {
			t.Errorf("exit code %d is documented in the usage text but not declared", code)
		}
	}
	// The wrapper's own codes start above the online installer's set (0,
	// 10-18), which it passes through unchanged; a new constant inside that
	// range would collide with a documented meaning.
	online := map[string]bool{"EXIT_OK": true, "EXIT_NOT_ROOT": true, "EXIT_UNSUPPORTED_OS": true,
		"EXIT_BAD_ARGUMENTS": true, "EXIT_CHECKSUM_FAILED": true, "EXIT_SERVICE_FAILED": true}
	for code, name := range declared {
		if code <= 18 && !online[name] {
			t.Errorf("%s = %d sits inside the online installer's documented range with a new "+
				"meaning; callers reading the README would misread it", name, code)
		}
	}
}

// TestFullUninstallStillConfirms: --full-uninstall names everything for
// deletion but must go through the delegated installer's own confirmation,
// so an interactive full uninstall still asks and only --yes is silent.
func TestFullUninstallStillConfirms(t *testing.T) {
	script := readOfflineScript(t, "install_offline.sh")

	if !strings.Contains(script, "--uninstall --purge-tunnels --purge-data --remove-cli") {
		t.Error("--full-uninstall no longer forwards the three purge flags, so it does not " +
			"remove what its name promises")
	}
	// It must not smuggle in --yes: the confirmation is the delegated
	// installer's, and adding --yes here would delete data silently.
	block := sectionBetween(script, "full-uninstall)", "esac")
	if strings.Contains(block, "--yes") {
		t.Error("the full-uninstall branch passes --yes itself, so an interactive full " +
			"uninstall would delete the database without asking")
	}
}

// TestTheBuilderRefusesToCrossReleases: a 22.04 bundle built on a 24.04
// host would carry 24.04 packages under a 22.04 label. The builder must
// compare the requested release against the running system and stop.
func TestTheBuilderRefusesToCrossReleases(t *testing.T) {
	script := readOfflineScript(t, "build_bundle.sh")

	if !strings.Contains(script, `[[ "$HOST_VERSION" == "$UBUNTU" ]] ||`) {
		t.Error("build_bundle.sh no longer refuses to build for a release other than the " +
			"running one; the package closure would describe the wrong Ubuntu")
	}
	for _, artefact := range []string{"Packages", "Packages.gz", "Release", "checksums.sha256", "manifest.json", "README_OFFLINE.md"} {
		if !strings.Contains(script, artefact) {
			t.Errorf("build_bundle.sh no longer produces %s", artefact)
		}
	}
	// The packed bundle is verified by re-extraction, not trusted.
	if !strings.Contains(script, `tar -xzf "$TARBALL" -C "$VERIFY"`) {
		t.Error("the builder no longer re-extracts the packed tarball to verify it; a tarball " +
			"that lists is not yet a tarball that restores")
	}
}

// TestTheWorkflowBuildsEachReleaseInItsOwnContainer: ubuntu-latest is
// whatever GitHub says it is; the bundles are for exactly 22.04 and 24.04,
// and each must be resolved inside a container of its own release.
func TestTheWorkflowBuildsEachReleaseInItsOwnContainer(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "offline-bundles.yml"))
	if err != nil {
		t.Fatalf("reading the workflow: %v", err)
	}
	workflow := strings.ReplaceAll(string(body), "\r\n", "\n")

	for _, needed := range []struct{ fragment, why string }{
		{"\non:\n  push:", "the workflow no longer runs on every push"},
		{"workflow_dispatch:", "the workflow can no longer be started by hand"},
		{`ubuntu: ["22.04", "24.04"]`, "the matrix no longer covers both supported releases"},
		{"image: ubuntu:${{ matrix.ubuntu }}", "bundles are no longer built inside the target release's own container"},
		{"permissions:\n  contents: read", "the default permissions are no longer least-privilege"},
		{"--flavor standard", "the standard bundle is no longer built"},
		{"--flavor bootstrap", "the bootstrap bundle is no longer built"},
		{"validate_bundle.sh", "bundles are no longer validated before upload"},
		{"--install-test", "validation no longer performs the in-container offline install"},
		{"if: startsWith(github.ref, 'refs/tags/')", "release publishing is no longer gated to tags"},
	} {
		if !strings.Contains(workflow, needed.fragment) {
			t.Errorf("%s (missing %q)", needed.why, needed.fragment)
		}
	}

	// Validation has to precede the upload, or a failed bundle publishes.
	validate := strings.Index(workflow, "Validate the bootstrap bundle")
	upload := strings.Index(workflow, "name: tunnel-panel-${{ needs.build.outputs.version }}")
	if validate < 0 || upload < 0 || validate > upload {
		t.Error("bundle validation does not precede the artifact upload; a bundle that fails " +
			"validation could still be published")
	}

	// contents: write may appear once, in the tag-gated release job only.
	if strings.Count(workflow, "contents: write") > 1 {
		t.Error("more than one job requests contents: write")
	}
}
