package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/drs/gre-panel/internal/address"
	"github.com/drs/gre-panel/internal/config"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/rules"
	"github.com/drs/gre-panel/internal/safety"
)

// How long to wait for the panel to answer at its new address, and how often to
// ask. Thirty seconds is generous: a restart on these hosts takes about two,
// and the cost of being wrong in this direction is an unnecessary rollback of a
// change that was actually fine.
const (
	comeBackTimeout  = 30 * time.Second
	comeBackInterval = 500 * time.Millisecond
)

// addressChange is one requested move, and its outcome.
type addressChange struct {
	FromPort    int    `json:"from_port"`
	FromWebPath string `json:"from_web_path"`
	ToPort      int    `json:"to_port"`
	ToWebPath   string `json:"to_web_path"`
	URL         string `json:"url"`
	PreviousURL string `json:"previous_url"`
	Applied     bool   `json:"applied"`
	RolledBack  bool   `json:"rolled_back"`
	Restarted   bool   `json:"restarted"`
	Detail      string `json:"detail"`
}

// setAddress is the whole procedure, shared by set-port, set-web-path and the
// menu.
//
// The order is fixed and each step exists because of a way this goes wrong:
//
//	validate      a port that cannot be bound is refused now, not discovered
//	              at the next boot on a panel nobody can reach
//	announce      the new URL is printed before anything changes, because the
//	              operator is about to lose the connection they are on
//	store         the database, which is the source of truth
//	sync the file /etc/gre-panel.env is kept in step so it does not lie; the
//	              seed is refreshed with it so the panel does not read its own
//	              change as an edit
//	restart       systemctl, from outside the panel's cgroup
//	verify        the panel must answer ITS OWN health envelope at the new
//	              address; anything else is not proof it moved
//	roll back     on failure, put everything back and say whether that worked
func (a *app) setAddress(ctx context.Context, wantPort int, wantWebPath string) (*addressChange, error) {
	env, err := readPanelEnv(a.envPath)
	if err != nil {
		return nil, err
	}
	database, err := a.openDB(env)
	if err != nil {
		return nil, err
	}
	defer database.Close() //nolint:errcheck // read-write, closed on the way out

	stored, err := address.Load(ctx, database)
	if err != nil {
		return nil, err
	}
	seed := address.Seed{Port: env.Port, WebPath: env.WebPath, PortProvided: env.PortSet, WebPathProvided: env.WebPathSet}
	current := address.Resolve(stored, seed)

	change := &addressChange{
		FromPort: current.Port, FromWebPath: current.WebPath,
		ToPort: wantPort, ToWebPath: wantWebPath,
		PreviousURL: address.URL("http", a.publicHost(env), current.Port, current.WebPath),
		URL:         address.URL("http", a.publicHost(env), wantPort, wantWebPath),
	}

	if wantPort == current.Port && wantWebPath == current.WebPath {
		change.Detail = "The panel is already at that address; nothing was changed."
		change.Applied = true
		return change, nil
	}

	if err := a.validatePort(ctx, env, current.Port, wantPort); err != nil {
		return nil, err
	}

	// Announce before applying. This is the last moment the operator's current
	// connection is guaranteed to work.
	a.sayf("The panel will move to:  %s", change.URL)
	a.sayf("If it does not come back there, it will be put back at:  %s", change.PreviousURL)
	if !a.assumeYes {
		ok, err := a.confirm(ctx, "Apply this change?")
		if err != nil {
			return nil, err
		}
		if !ok {
			change.Detail = "Nothing was changed."
			return change, nil
		}
	}

	previousEnvPort, _ := env.file.Get(config.EnvBindPort)
	previousEnvWebPath, hadWebPath := env.file.Get(config.EnvWebPath)

	if err := address.Set(ctx, database, wantPort, wantWebPath, seed); err != nil {
		return nil, err
	}
	newSeed := address.Seed{Port: wantPort, WebPath: wantWebPath}
	if err := a.syncEnvFile(env, database, ctx, wantPort, wantWebPath, newSeed); err != nil {
		return nil, err
	}

	service := readServiceState(ctx)
	if !service.Installed {
		change.Applied = true
		change.Detail = "The new address was stored. The panel's service is not installed here, " +
			"so there was nothing to restart."
		return change, nil
	}

	a.sayf("Restarting %s", serviceName)
	restartErr := restartService(ctx)
	change.Restarted = restartErr == nil

	healthURL := address.HealthURL("http", a.loopbackHost(env), wantPort, wantWebPath)
	waitErr := address.WaitForHealth(ctx, http.DefaultClient, healthURL, comeBackTimeout, comeBackInterval)
	if restartErr == nil && waitErr == nil {
		change.Applied = true
		change.Detail = "The panel answered at the new address."
		a.audit(ctx, database, model.AuditActionPanelAddressChange, true, map[string]any{
			"port": wantPort, "web_path": wantWebPath,
			"previous_port": current.Port, "previous_web_path": current.WebPath,
			"actor": "tnp",
		}, "")
		return change, nil
	}

	// It did not come back. Put everything back the way it was, and be explicit
	// about whether that worked — an operator who is told "rolled back" and is
	// still locked out is worse off than one who is told the truth.
	failure := waitErr
	if restartErr != nil {
		failure = restartErr
	}
	a.sayf("The panel did not answer at %s: %v", healthURL, failure)
	a.sayf("Rolling back to %s", change.PreviousURL)

	change.RolledBack = true
	if err := address.Set(ctx, database, current.Port, current.WebPath, seed); err != nil {
		change.Detail = fmt.Sprintf("The panel did not come back at the new address (%v), and the "+
			"stored address could not be put back either (%v). Fix %s by hand.", failure, err, a.dbPath(env))
		return change, errRollbackFailed
	}
	restoreEnv(env, previousEnvPort, previousEnvWebPath, hadWebPath)
	if err := env.file.Write(); err != nil {
		a.sayf("warning: %s could not be restored: %v", a.envPath, err)
	}
	if err := restartService(ctx); err != nil {
		change.Detail = fmt.Sprintf("The panel did not come back at the new address (%v), the old "+
			"address was restored, and the service could not be restarted (%v).", failure, err)
		return change, errRollbackFailed
	}

	oldHealth := address.HealthURL("http", a.loopbackHost(env), current.Port, current.WebPath)
	if err := address.WaitForHealth(ctx, http.DefaultClient, oldHealth, comeBackTimeout, comeBackInterval); err != nil {
		change.Detail = fmt.Sprintf("The panel did not come back at the new address (%v), and it is "+
			"not answering at the old one either (%v). The journal says:\n%s",
			failure, err, journalTail(ctx, 20))
		return change, errRollbackFailed
	}

	change.Detail = fmt.Sprintf("The panel did not answer at the new address, so the change was "+
		"rolled back and it is serving at %s again. The reason was: %v", change.PreviousURL, failure)
	a.audit(ctx, database, model.AuditActionPanelAddressChange, false, map[string]any{
		"port": wantPort, "web_path": wantWebPath,
		"previous_port": current.Port, "previous_web_path": current.WebPath,
		"actor": "tnp", "rolled_back": true,
	}, failure.Error())
	return change, errChangeRolledBack
}

// restoreEnv puts the two keys back exactly as they were, including the case
// where GRE_PANEL_WEB_PATH was not in the file at all.
func restoreEnv(env *panelEnv, port, webPath string, hadWebPath bool) {
	env.file.Set(config.EnvBindPort, port)
	if hadWebPath {
		env.file.Set(config.EnvWebPath, webPath)
		return
	}
	// It was absent, and absent means the root. Writing an empty value says the
	// same thing and keeps the file explicit, which is better than the file
	// being silent about where the panel is.
	env.file.Set(config.EnvWebPath, "")
}

// syncEnvFile keeps /etc/gre-panel.env saying what is actually in effect.
//
// The panel cannot do this — /etc is read-only under its unit — so a change
// made in the browser leaves the file behind and the panel reports the
// disagreement instead. The CLI is not sandboxed, so when it is the one making
// the change it keeps the two in step, and refreshes the stored seed to match
// so the next start does not read the file it just wrote as an operator edit.
func (a *app) syncEnvFile(env *panelEnv, database dbHandle, ctx context.Context,
	port int, webPath string, seed address.Seed) error {

	env.file.Set(config.EnvBindPort, fmt.Sprintf("%d", port))
	env.file.Set(config.EnvWebPath, webPath)
	if err := env.file.Write(); err != nil {
		return err
	}
	return address.Set(ctx, database, port, webPath, seed)
}

// validatePort refuses a port before anything is written.
func (a *app) validatePort(ctx context.Context, env *panelEnv, currentPort, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("a port must be between 1 and 65535; %d is not", port)
	}
	if port == currentPort {
		return nil
	}

	// The same guard the panel uses, so the CLI cannot be the way around a
	// refusal the interface enforces. Moving the panel onto the live SSH port
	// locks the machine exactly as forwarding it would.
	guard := safety.NewRouteGuard(currentPort, rules.NewSocketReader(), dataDir+"/rules")
	for _, p := range guard.ProtectedPorts(ctx) {
		if p.Port == port && p.Port != currentPort {
			return fmt.Errorf("port %d cannot be used: %s", port, p.Reason)
		}
	}

	if err := address.Probe(env.Host, port); err != nil {
		return fmt.Errorf("port %d cannot be bound on %s, so the panel would not come back on it: %w",
			port, env.Host, err)
	}
	return nil
}
