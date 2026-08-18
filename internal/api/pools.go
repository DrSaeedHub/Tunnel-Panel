package api

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/drs/gre-panel/internal/alloc"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/validate"
)

// poolResponse is one address pool with what it can actually hold, so the
// frontend never has to work out the addressing scheme for itself.
type poolResponse struct {
	alloc.Pool
	Capacity alloc.PoolCapacity `json:"capacity"`
	// InUse counts how many of its subnets are taken.
	InUse int `json:"in_use"`
}

func (s *Server) handleListPools(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pools, err := s.tunnels.Repo().Pools(ctx)
	if err != nil {
		s.writeDomainError(w, r, err)
		return
	}
	alloc.SortPools(pools)

	used, err := s.tunnels.Alloc().UsedAddressSet(ctx)
	if err != nil {
		used = map[netip.Addr]bool{}
	}
	prefixLen := s.tunnels.Alloc().DefaultPrefixLength()

	out := make([]poolResponse, 0, len(pools))
	for _, pool := range pools {
		item := poolResponse{Pool: pool, Capacity: alloc.Describe(pool, prefixLen)}
		if prefix, err := pool.Prefix(); err == nil {
			for addr := range used {
				if prefix.Contains(addr) {
					item.InUse++
				}
			}
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pools":              out,
		"total":              len(out),
		"default_prefix_len": prefixLen,
	})
}

// poolRequest is the body of a pool create or update.
type poolRequest struct {
	AddressPoolTitle string `json:"address_pool_title"`
	Cidr             string `json:"cidr"`
	PrefixLength     int    `json:"prefix_length"`
	IsEnabled        *bool  `json:"is_enabled,omitempty"`
	Description      string `json:"description,omitempty"`
}

// validatePool checks a pool before it is stored. The public-range flag is
// measured from the range rather than taken from the request: whether a block
// is globally routable is a fact, not a preference.
func validatePool(req poolRequest) (alloc.Pool, *validate.Errors) {
	errs := &validate.Errors{}
	pool := alloc.Pool{
		Title:        strings.TrimSpace(req.AddressPoolTitle),
		Cidr:         strings.TrimSpace(req.Cidr),
		PrefixLength: req.PrefixLength,
		Description:  req.Description,
		IsEnabled:    true,
	}
	if req.IsEnabled != nil {
		pool.IsEnabled = *req.IsEnabled
	}

	if pool.Title == "" {
		errs.Add("address_pool_title", CodeValidationFailed, "A pool needs a name.", nil)
	}
	prefix, err := netip.ParsePrefix(pool.Cidr)
	if err != nil {
		errs.Add("cidr", validate.CodeInvalidAddress,
			"The range must be written in CIDR form, such as 172.17.0.0/16.", nil)
		return pool, errs
	}
	pool.Cidr = prefix.Masked().String()
	pool.IsPublicRange = validate.IsPublicRange(prefix.Addr())

	if pool.PrefixLength == 0 {
		// A pool that does not say how big its subnets are gets the smallest
		// point-to-point subnet its family supports.
		pool.PrefixLength = 30
		if !prefix.Addr().Is4() {
			pool.PrefixLength = 127
		}
	}
	if _, err := alloc.Capacity(prefix.Masked(), pool.PrefixLength); err != nil {
		errs.Add("prefix_length", validate.CodeInvalidPrefixLen, capitalise(err.Error())+".", nil)
	}
	return pool, errs
}

func (s *Server) handleCreatePool(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req poolRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	pool, errs := validatePool(req)
	if !errs.Empty() {
		s.writeDomainError(w, r, errs)
		return
	}

	id, err := s.tunnels.Repo().InsertPool(r.Context(), pool)
	if err != nil {
		s.writeDomainError(w, r, err)
		return
	}
	pool.AddressPoolID = id

	s.auditTunnel(r, model.AuditActionPoolChange, pool.Title, req, nil, nil, start)
	writeJSON(w, http.StatusCreated, poolResponse{
		Pool:     pool,
		Capacity: alloc.Describe(pool, pool.PrefixLength),
	})
}

func (s *Server) handleGetPool(w http.ResponseWriter, r *http.Request) {
	pool, ok := s.poolFromPath(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, poolResponse{
		Pool: pool, Capacity: alloc.Describe(pool, pool.PrefixLength),
	})
}

func (s *Server) handleUpdatePool(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	existing, ok := s.poolFromPath(w, r)
	if !ok {
		return
	}
	var req poolRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	pool, errs := validatePool(req)
	if !errs.Empty() {
		s.writeDomainError(w, r, errs)
		return
	}
	pool.AddressPoolID = existing.AddressPoolID

	if err := s.tunnels.Repo().UpdatePool(r.Context(), pool); err != nil {
		s.writeDomainError(w, r, err)
		return
	}
	s.auditTunnel(r, model.AuditActionPoolChange, pool.Title, req, nil, nil, start)
	writeJSON(w, http.StatusOK, poolResponse{
		Pool: pool, Capacity: alloc.Describe(pool, pool.PrefixLength),
	})
}

func (s *Server) handleDeletePool(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	pool, ok := s.poolFromPath(w, r)
	if !ok {
		return
	}
	if err := s.tunnels.Repo().DeletePool(r.Context(), pool.AddressPoolID); err != nil {
		// A pool a tunnel still points at is a conflict the operator can resolve,
		// not an internal failure.
		writeError(w, http.StatusConflict, CodeConflict, capitalise(err.Error())+".", "", nil)
		return
	}
	s.auditTunnel(r, model.AuditActionPoolChange, pool.Title, map[string]any{"deleted": pool.Cidr},
		nil, nil, start)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "address_pool_id": pool.AddressPoolID})
}

// handleNextFreePool answers "what would the next tunnel from this pool get?"
// without allocating anything.
func (s *Server) handleNextFreePool(w http.ResponseWriter, r *http.Request) {
	pool, ok := s.poolFromPath(w, r)
	if !ok {
		return
	}

	prefixLen := s.tunnels.Alloc().DefaultPrefixLength()
	if raw := r.URL.Query().Get("prefix_length"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			prefixLen = n
		}
	}

	allocation, err := s.tunnels.Alloc().NextFree(r.Context(), pool, prefixLen)
	if err != nil {
		writeError(w, http.StatusConflict, CodeAllocation, capitalise(err.Error())+".",
			"address_pool_id", map[string]any{"address_pool_id": pool.AddressPoolID})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"allocation": allocation,
		"capacity":   alloc.Describe(pool, prefixLen),
		"warnings":   warningsOf(allocation.Warnings),
	})
}

func (s *Server) poolFromPath(w http.ResponseWriter, r *http.Request) (alloc.Pool, bool) {
	raw := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest,
			"The pool identifier in the path is not a number.", "id", nil)
		return alloc.Pool{}, false
	}
	pool, err := s.tunnels.Repo().PoolByID(r.Context(), id)
	if err != nil {
		s.writeDomainError(w, r, err)
		return alloc.Pool{}, false
	}
	return pool, true
}
