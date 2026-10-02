package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/drs/gre-panel/internal/config"
	"github.com/drs/gre-panel/internal/i18n"
)

// DefaultReleaseBase mirrors the installer's own default, and cmd/tnp's copy of
// it. A test pins the three literals together, because a release base that
// disagrees with the installer's would have the panel checking one repository
// and installing from another.
const DefaultReleaseBase = "https://github.com/DrSaeedHub/Tunnel-Panel/releases/download"

// CLIEnvPath is where the installer records what it installed from. Reading it
// is how the check follows an installation that came from a fork or a mirror
// rather than assuming the default above.
const CLIEnvPath = "/usr/local/share/gre-panel/cli.env"

// releaseAPI renders the API endpoint that names a repository's current
// release. GitHub serves the API and the downloads from different hosts, so
// this cannot be derived from the release base by string surgery alone.
const releaseAPI = "https://api.github.com/repos/%s/releases/latest"

// notesLimit caps how much of a release body is kept. Release notes are shown
// in a dialog, not read from a file, and a repository is free to publish a
// novel there.
const notesLimit = 8000

// checkTimeout bounds one check. The release host is on the public internet and
// the panel is often on a server that cannot reach it at all; a check that hung
// would hold a request open for as long as the socket took to give up.
const checkTimeout = 15 * time.Second

// Release is what the release host says its current release is.
type Release struct {
	Version     string `json:"version"`
	Name        string `json:"name,omitempty"`
	URL         string `json:"url,omitempty"`
	PublishedAt string `json:"published_at,omitempty"`
	Notes       string `json:"notes,omitempty"`
}

// Status is the complete answer to "is there a newer panel", including the
// reasons it might not be answerable.
type Status struct {
	CurrentVersion  string  `json:"current_version"`
	Latest          Release `json:"latest"`
	UpdateAvailable bool    `json:"update_available"`
	// CheckedAt is when the release host was last reached, empty when it never
	// has been. A status with no CheckedAt and no Error has simply not been
	// looked up yet.
	CheckedAt string `json:"checked_at,omitempty"`
	// Checking reports that a lookup is in flight, so a caller polling this
	// knows to ask again rather than concluding the check produced nothing.
	Checking bool `json:"checking"`
	// Error is the last failure, in the operator's terms. A panel with no
	// outbound access reaches this on every check and it is not a fault.
	Error string `json:"error,omitempty"`
	// Note explains a "no" that is not simply "you are up to date" — a build
	// that came from no release cannot be compared against one.
	Note string `json:"note,omitempty"`
	// Source is the repository the answer came from, so an operator can see
	// that a fork's installation is checking the fork.
	Source string `json:"source"`
	// Enabled reports whether the panel checks on its own. When it is false the
	// only checks that happen are the ones an operator asks for.
	Enabled bool `json:"enabled"`
}

// Settings is the slice of the settings store this package reads. Taking it as
// an interface keeps the package testable without a database.
type Settings interface {
	Bool(key string) bool
	Int(key string) int64
}

// CheckerDeps is what a Checker needs.
type CheckerDeps struct {
	// CurrentVersion is the running build's stamp.
	CurrentVersion string
	// ReleaseBase is where the installation was installed from. Empty means
	// read it from CLIEnvPath, which is the normal case.
	ReleaseBase string
	// APIURL overrides the derived endpoint entirely, for a test.
	APIURL   string
	Client   *http.Client
	Settings Settings
	Log      *slog.Logger
	// Now is injectable so a test can age the cache without sleeping.
	Now func() time.Time
}

// Checker holds the last answer from the release host and decides when to ask
// again.
//
// The cache is the point. This is read every time a dashboard is opened, and a
// panel that asked GitHub on each of those would be both slow and rude; the
// interval setting is what an operator turns down when they want to know
// sooner. Nothing here ever blocks a request on the network: a stale cache is
// refreshed in the background and the caller is told a check is running.
type Checker struct {
	current  string
	apiURL   string
	source   string
	client   *http.Client
	settings Settings
	log      *slog.Logger
	now      func() time.Time

	mu      sync.Mutex
	latest  Release
	checked time.Time
	// lastErr is the last check's failure, kept as an error rather than as
	// text so it is said in the language of whoever reads it.
	lastErr  error
	checking bool
}

// NewChecker builds a checker. It resolves the repository once, at startup,
// because the installation it belongs to does not change while the panel runs.
func NewChecker(d CheckerDeps) *Checker {
	now := d.Now
	if now == nil {
		now = time.Now
	}
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	client := d.Client
	if client == nil {
		client = &http.Client{Timeout: checkTimeout}
	}

	base := d.ReleaseBase
	if base == "" {
		base = installedReleaseBase()
	}
	repo := repositoryOf(base)
	api := d.APIURL
	if api == "" {
		api = fmt.Sprintf(releaseAPI, repo)
	}

	return &Checker{
		current: d.CurrentVersion, apiURL: api, source: repo,
		client: client, settings: d.Settings, log: log, now: now,
	}
}

// installedReleaseBase reads what the installer recorded about itself.
//
// An offline bundle records a directory on this host, which only ever holds the
// one version it shipped with: asking it for something newer is asking a
// snapshot of the past for the future. cmd/tnp's update path reaches past such
// a base to the real release host, and this agrees with it, so the version the
// check offers is the version the install would fetch.
func installedReleaseBase() string {
	get := config.EnvFileGetenv(CLIEnvPath, nil)
	base := strings.TrimSpace(get("GRE_PANEL_RELEASE_BASE"))
	if base == "" || isLocalReleaseBase(base) {
		return DefaultReleaseBase
	}
	return base
}

// isLocalReleaseBase mirrors install.sh's source_is_remote check and cmd/tnp's
// copy of it.
func isLocalReleaseBase(base string) bool {
	return strings.HasPrefix(base, "file://") || strings.HasPrefix(base, "/")
}

// repositoryOf pulls owner/name out of a release base. Anything that is not a
// GitHub release URL falls back to the default repository rather than producing
// an endpoint that cannot answer: a mirror serving the binaries over plain HTTP
// still publishes its releases here.
func repositoryOf(base string) string {
	fallback := "DrSaeedHub/Tunnel-Panel"
	parsed, err := url.Parse(strings.TrimSpace(base))
	if err != nil || parsed.Host != "github.com" {
		return fallback
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return fallback
	}
	return parts[0] + "/" + parts[1]
}

// Source is the repository this checker asks about.
func (c *Checker) Source() string { return c.source }

// Enabled reports whether automatic checking is on. An operator who turns it
// off still gets the button; what stops is the panel reaching out by itself.
func (c *Checker) Enabled() bool {
	if c.settings == nil {
		return true
	}
	return c.settings.Bool("system.update_check_enabled")
}

// interval is how long an answer is good for.
func (c *Checker) interval() time.Duration {
	hours := int64(6)
	if c.settings != nil {
		if v := c.settings.Int("system.update_check_interval_hours"); v > 0 {
			hours = v
		}
	}
	return time.Duration(hours) * time.Hour
}

// Status returns what is known now, and starts a background refresh when the
// answer has aged past the interval.
//
// It never waits: the caller is a request handler, and the honest answer to
// "what is the latest version" while the network is being asked is "I am
// asking", which Checking carries.
func (c *Checker) Status(ctx context.Context) Status {
	if c.Enabled() && c.stale() {
		c.refreshInBackground(ctx)
	}
	return c.snapshot(ctx)
}

// Refresh asks the release host now and waits for the answer. This is the
// explicit "check again" button, where waiting is what the operator asked for.
func (c *Checker) Refresh(ctx context.Context) Status {
	if !c.begin() {
		// Another check is already in flight; its answer is the one this
		// caller would have got anyway.
		return c.snapshot(ctx)
	}
	c.fetch(ctx)
	return c.snapshot(ctx)
}

// stale reports whether the cached answer is old enough to ask again. A failed
// check counts as an answer for this purpose — otherwise a panel with no
// outbound access would retry on every single request.
func (c *Checker) stale() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.checking {
		return false
	}
	if c.checked.IsZero() {
		return true
	}
	return c.now().Sub(c.checked) >= c.interval()
}

// begin claims the right to check, so two callers cannot ask at once.
func (c *Checker) begin() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.checking {
		return false
	}
	c.checking = true
	return true
}

func (c *Checker) refreshInBackground(ctx context.Context) {
	if !c.begin() {
		return
	}
	// Deliberately not the request's context: the check outlives the request
	// that noticed it was due, and cancelling it when the browser navigates
	// away would mean the answer never arrives.
	go func() {
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), checkTimeout)
		defer cancel()
		c.fetch(bg)
	}()
}

// fetch performs one lookup and records the outcome. It always clears the
// in-flight flag, so a failure cannot wedge the checker into "checking".
func (c *Checker) fetch(ctx context.Context) {
	release, err := c.lookup(ctx)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.checking = false
	c.checked = c.now()
	if err != nil {
		c.lastErr = err
		c.log.Debug("checking for a panel update failed", "error", err, "source", c.source)
		return
	}
	c.lastErr = nil
	c.latest = release
}

// checkFailure is a check that produced no answer. It is said when it is
// reported rather than when it happened: the answer is kept for hours and read
// by whoever opens the dashboard next, in whatever language they read it in.
type checkFailure struct {
	say func(ctx context.Context) string
	err error
}

// Error is the English, which is what the log gets.
func (f *checkFailure) Error() string {
	return f.say(i18n.WithLanguage(context.Background(), i18n.English))
}

func (f *checkFailure) Unwrap() error { return f.err }

// failed records why a check produced no answer. cause is what went wrong
// underneath, or nil when the release host's answer was itself the problem.
func failed(cause error, say func(ctx context.Context) string) error {
	return &checkFailure{say: say, err: cause}
}

// sayFailure is a check's failure in the language ctx carries.
func sayFailure(ctx context.Context, err error) string {
	var failure *checkFailure
	if errors.As(err, &failure) {
		return failure.say(ctx)
	}
	return err.Error()
}

// githubRelease is the half of GitHub's release object this reads.
type githubRelease struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	HTMLURL     string `json:"html_url"`
	PublishedAt string `json:"published_at"`
	Body        string `json:"body"`
	Draft       bool   `json:"draft"`
	Prerelease  bool   `json:"prerelease"`
}

func (c *Checker) lookup(ctx context.Context) (Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURL, nil)
	if err != nil {
		return Release{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	// GitHub rejects a request with no User-Agent outright, and an anonymous
	// one is rate limited by address; naming the panel is what makes a refused
	// check readable in their logs and ours.
	req.Header.Set("User-Agent", "gre-panel/"+c.current)

	resp, err := c.client.Do(req)
	if err != nil {
		return Release{}, failed(err, func(ctx context.Context) string {
			return i18n.T(ctx, "the release host could not be reached: %v", err)
		})
	}
	defer resp.Body.Close() //nolint:errcheck // read-only

	source, status := c.source, resp.StatusCode
	switch {
	case status == http.StatusNotFound:
		return Release{}, failed(nil, func(ctx context.Context) string {
			return i18n.T(ctx, "%s has no releases, or is not a repository this panel can see", source)
		})
	case status == http.StatusForbidden || status == http.StatusTooManyRequests:
		return Release{}, failed(nil, func(ctx context.Context) string {
			return i18n.T(ctx, "the release host is rate limiting this address; the next check will try again")
		})
	case status != http.StatusOK:
		return Release{}, failed(nil, func(ctx context.Context) string {
			return i18n.T(ctx, "the release host answered HTTP %d", status)
		})
	}

	var body githubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return Release{}, failed(err, func(ctx context.Context) string {
			return i18n.T(ctx, "the release host's answer could not be read: %v", err)
		})
	}
	if strings.TrimSpace(body.TagName) == "" {
		return Release{}, failed(nil, func(ctx context.Context) string {
			return i18n.T(ctx, "the release host named no version")
		})
	}

	notes := body.Body
	if len(notes) > notesLimit {
		notes = notes[:notesLimit] + "\n…"
	}
	return Release{
		Version:     strings.TrimSpace(body.TagName),
		Name:        strings.TrimSpace(body.Name),
		URL:         body.HTMLURL,
		PublishedAt: body.PublishedAt,
		Notes:       notes,
	}, nil
}

// snapshot renders the current knowledge as the answer an API caller gets, in
// the language ctx carries.
func (c *Checker) snapshot(ctx context.Context) Status {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := Status{
		CurrentVersion: c.current,
		Latest:         c.latest,
		Checking:       c.checking,
		Source:         c.source,
		Enabled:        c.Enabled(),
	}
	if c.lastErr != nil {
		out.Error = sayFailure(ctx, c.lastErr)
	}
	if !c.checked.IsZero() {
		out.CheckedAt = c.checked.UTC().Format(time.RFC3339)
	}
	if c.latest.Version == "" {
		return out
	}

	out.UpdateAvailable = Newer(c.current, c.latest.Version)
	if out.UpdateAvailable {
		return out
	}
	// A "no" that is not "up to date" is worth saying out loud, because the
	// two look identical from a footer that only shows a version number.
	if running, ok := ParseVersion(c.current); !ok || !running.IsRelease() {
		out.Note = i18n.T(ctx, "This build did not come from a release, so it cannot be compared against one.")
	}
	return out
}
