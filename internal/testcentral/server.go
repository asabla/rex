//go:build central_e2e

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/asabla/rex/internal/core/identity"
	"github.com/asabla/rex/internal/core/storage/eventlog"
	"github.com/asabla/rex/internal/core/sync/proto"
)

const bearerPrefix = "Bearer "

type Options struct {
	Keystore *Keystore
}

type Server struct {
	store    *MemoryStore
	gitStore *MemoryGitStore
	keystore *Keystore
	keypair  identity.Keypair
	actor    identity.Actor
	auth     *authState
	mux      *http.ServeMux
}

func New(opts Options) (*Server, error) {
	kp, err := identity.GenerateKeypair("rex-central", nil)
	if err != nil {
		return nil, err
	}
	ks := opts.Keystore
	if ks == nil {
		ks = NewKeystore()
	}
	s := &Server{
		store:    NewStore(),
		gitStore: NewMemoryGitStore(),
		keystore: ks,
		keypair:  kp,
		actor:    identity.Actor{Role: identity.RoleCentral, Fingerprint: kp.Fingerprint()},
		auth:     newAuthState(),
		mux:      http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("/sync/state", s.handleState)
	s.mux.HandleFunc("/sync/events", s.handleEvents)
	s.mux.HandleFunc("/sync/git", s.handleGitPush)
	s.mux.HandleFunc("/sync/git/ws/", s.handleGitPull)
	s.mux.HandleFunc("/auth/challenge", s.handleAuthChallenge)
	s.mux.HandleFunc("/auth/verify", s.handleAuthVerify)
}

func (s *Server) Handler() http.Handler { return s.mux }
func (s *Server) Actor() identity.Actor { return s.actor }
func (s *Server) Store() *MemoryStore   { return s.store }
func (s *Server) GitStore() *MemoryGitStore {
	return s.gitStore
}

type MemoryStore struct {
	mu      sync.RWMutex
	records []eventlog.Record
	byID    map[string]int
}

func NewStore() *MemoryStore { return &MemoryStore{byID: make(map[string]int)} }

func (s *MemoryStore) Head(_ context.Context) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.records) == 0 {
		return "", nil
	}
	return s.records[len(s.records)-1].ID, nil
}

func (s *MemoryStore) Append(_ context.Context, rec eventlog.Record) (bool, error) {
	if rec.ID == "" {
		return false, errors.New("server: append requires a non-empty record id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.byID[rec.ID]; dup {
		return false, nil
	}
	s.byID[rec.ID] = len(s.records)
	s.records = append(s.records, rec)
	return true, nil
}

func (s *MemoryStore) AppendBatch(ctx context.Context, recs []eventlog.Record) ([]string, error) {
	added := make([]string, 0, len(recs))
	for _, rec := range recs {
		ok, err := s.Append(ctx, rec)
		if err != nil {
			return nil, err
		}
		if ok {
			added = append(added, rec.ID)
		}
	}
	return added, nil
}

func (s *MemoryStore) Since(_ context.Context, cursor string) ([]eventlog.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if cursor == "" {
		out := make([]eventlog.Record, len(s.records))
		copy(out, s.records)
		return out, nil
	}
	idx, ok := s.byID[cursor]
	if !ok {
		return nil, fmt.Errorf("server: unknown cursor: %q", cursor)
	}
	tail := s.records[idx+1:]
	out := make([]eventlog.Record, len(tail))
	copy(out, tail)
	return out, nil
}

func (s *MemoryStore) Len(_ context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.records), nil
}

func (s *MemoryStore) tailAfterOrAll(cursor string) []eventlog.Record {
	tail, err := s.Since(context.Background(), cursor)
	if err == nil {
		return tail
	}
	all, _ := s.Since(context.Background(), "")
	return all
}

type MemoryGitStore struct {
	mu   sync.RWMutex
	data map[string]map[string]proto.GitEntity
}

func NewMemoryGitStore() *MemoryGitStore {
	return &MemoryGitStore{data: make(map[string]map[string]proto.GitEntity)}
}

func (s *MemoryGitStore) Put(_ context.Context, workspaceID string, rec proto.GitEntity, _ string) error {
	if workspaceID == "" {
		return errors.New("server: workspace id required")
	}
	if rec.Path == "" {
		return errors.New("server: entity path required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data[workspaceID] == nil {
		s.data[workspaceID] = make(map[string]proto.GitEntity)
	}
	s.data[workspaceID][rec.Path] = rec
	return nil
}

func (s *MemoryGitStore) Get(_ context.Context, workspaceID, path string) (proto.GitEntity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ws := s.data[workspaceID]
	if ws == nil {
		return proto.GitEntity{}, errors.New("server: unknown entity")
	}
	rec, ok := ws[path]
	if !ok {
		return proto.GitEntity{}, errors.New("server: unknown entity")
	}
	return rec, nil
}

type Keystore struct {
	mu      sync.RWMutex
	byFP    map[string]ed25519.PublicKey
	handles map[string]string
}

func NewKeystore() *Keystore {
	return &Keystore{byFP: make(map[string]ed25519.PublicKey), handles: make(map[string]string)}
}

func (k *Keystore) Add(handle string, pub ed25519.PublicKey) (identity.Fingerprint, error) {
	fp, err := identity.FingerprintOf(pub)
	if err != nil {
		return identity.Fingerprint{}, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.byFP[fp.String()] = append(ed25519.PublicKey(nil), pub...)
	k.handles[fp.String()] = handle
	return fp, nil
}

func (k *Keystore) Empty() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.byFP) == 0
}

func (k *Keystore) Lookup(fp identity.Fingerprint) (ed25519.PublicKey, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	pub, ok := k.byFP[fp.String()]
	if !ok {
		return nil, false
	}
	return append(ed25519.PublicKey(nil), pub...), true
}

type challenge struct {
	nonce     string
	hostname  string
	expiresAt time.Time
}

type issuedToken struct {
	fingerprint identity.Fingerprint
	expiresAt   time.Time
}

type authState struct {
	mu         sync.Mutex
	challenges map[string]challenge
	tokens     map[string]issuedToken
}

func newAuthState() *authState {
	return &authState{
		challenges: make(map[string]challenge),
		tokens:     make(map[string]issuedToken),
	}
}

func (a *authState) issueChallenge(hostname string) (id string, ch challenge, err error) {
	idBytes := make([]byte, 16)
	nonceBytes := make([]byte, 32)
	if _, err = rand.Read(idBytes); err != nil {
		return "", challenge{}, err
	}
	if _, err = rand.Read(nonceBytes); err != nil {
		return "", challenge{}, err
	}
	id = hex.EncodeToString(idBytes)
	ch = challenge{nonce: hex.EncodeToString(nonceBytes), hostname: hostname, expiresAt: time.Now().Add(60 * time.Second)}
	a.mu.Lock()
	a.challenges[id] = ch
	a.mu.Unlock()
	return id, ch, nil
}

func (a *authState) consumeChallenge(id string) (challenge, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ch, ok := a.challenges[id]
	if !ok {
		return challenge{}, errors.New("unknown challenge")
	}
	delete(a.challenges, id)
	if time.Now().After(ch.expiresAt) {
		return challenge{}, errors.New("expired challenge")
	}
	return ch, nil
}

func (a *authState) issueToken(fp identity.Fingerprint) (string, time.Time, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	value := hex.EncodeToString(raw)
	expiresAt := time.Now().Add(15 * time.Minute)
	a.mu.Lock()
	a.tokens[value] = issuedToken{fingerprint: fp, expiresAt: expiresAt}
	a.mu.Unlock()
	return value, expiresAt, nil
}

func (a *authState) resolveToken(value string) (identity.Fingerprint, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	tok, ok := a.tokens[value]
	if !ok || time.Now().After(tok.expiresAt) {
		return identity.Fingerprint{}, errors.New("invalid token")
	}
	return tok.fingerprint, nil
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, proto.ErrCodeBadRequest, "GET only")
		return
	}
	head, _ := s.store.Head(r.Context())
	writeJSON(w, http.StatusOK, proto.StateResponse{
		HeadID:          head,
		Fingerprint:     s.actor.Fingerprint.String(),
		Actor:           s.actor.String(),
		ProtocolVersion: proto.ProtocolVersion,
	})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if s.keystore != nil && !s.keystore.Empty() {
		if _, err := s.requireToken(r); err != nil {
			writeError(w, http.StatusUnauthorized, proto.ErrCodeUnauthorized, err.Error())
			return
		}
	}
	switch r.Method {
	case http.MethodGet:
		s.handleEventsGet(w, r)
	case http.MethodPost:
		s.handleEventsPost(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, proto.ErrCodeBadRequest, "GET or POST only")
	}
}

func (s *Server) handleEventsGet(w http.ResponseWriter, r *http.Request) {
	recs, err := s.store.Since(r.Context(), r.URL.Query().Get("since"))
	if err != nil {
		writeError(w, http.StatusBadRequest, proto.ErrCodeBadRequest, "unknown cursor")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	for _, rec := range recs {
		frame, _ := json.Marshal(proto.SSEFrame{Record: rec})
		_, _ = fmt.Fprintf(w, "data: %s\n\n", frame)
	}
}

func (s *Server) handleEventsPost(w http.ResponseWriter, r *http.Request) {
	var req proto.PushRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, proto.ErrCodeBadRequest, "decode request: "+err.Error())
		return
	}
	head, _ := s.store.Head(r.Context())
	if req.Since != head {
		writeJSON(w, http.StatusConflict, proto.ConflictResponse{
			ServerHead:    head,
			DivergingTail: s.store.tailAfterOrAll(req.Since),
		})
		return
	}
	if s.keystore != nil && !s.keystore.Empty() {
		fp, err := s.requireToken(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, proto.ErrCodeUnauthorized, err.Error())
			return
		}
		if err := s.verifyEvents(fp, req.Events); err != nil {
			writeError(w, http.StatusUnauthorized, proto.ErrCodeUnauthorized, err.Error())
			return
		}
	}
	added, err := s.store.AppendBatch(r.Context(), req.Events)
	if err != nil {
		writeError(w, http.StatusInternalServerError, proto.ErrCodeServerError, err.Error())
		return
	}
	head, _ = s.store.Head(r.Context())
	writeJSON(w, http.StatusOK, proto.PushResponse{HeadID: head, Accepted: len(added), Duplicates: len(req.Events) - len(added)})
}

func (s *Server) verifyEvents(fp identity.Fingerprint, events []eventlog.Record) error {
	pub, ok := s.keystore.Lookup(fp)
	if !ok {
		return errors.New("unknown fingerprint")
	}
	wantActor := identity.Actor{Role: identity.RoleLocal, Fingerprint: fp}.String()
	for _, rec := range events {
		if rec.Actor != wantActor {
			return fmt.Errorf("actor %q does not match authenticated fingerprint", rec.Actor)
		}
		if err := eventlog.VerifyRecord(rec, func(payload, sig []byte) bool {
			return identity.Verify(pub, payload, sig)
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleGitPull(w http.ResponseWriter, r *http.Request) {
	if s.keystore != nil && !s.keystore.Empty() {
		if _, err := s.requireToken(r); err != nil {
			writeError(w, http.StatusUnauthorized, proto.ErrCodeUnauthorized, err.Error())
			return
		}
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, proto.ErrCodeBadRequest, "GET only")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/sync/git/ws/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 {
		writeError(w, http.StatusBadRequest, proto.ErrCodeBadRequest, "workspace and entity required")
		return
	}
	rec, err := s.gitStore.Get(r.Context(), parts[0], parts[1])
	if err != nil {
		writeError(w, http.StatusNotFound, proto.ErrCodeGitUnknownEntity, "entity not found")
		return
	}
	writeJSON(w, http.StatusOK, proto.GitPullResponse{Entity: rec})
}

func (s *Server) handleGitPush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, proto.ErrCodeBadRequest, "POST only")
		return
	}
	if s.keystore != nil && !s.keystore.Empty() {
		if _, err := s.requireToken(r); err != nil {
			writeError(w, http.StatusUnauthorized, proto.ErrCodeUnauthorized, err.Error())
			return
		}
	}
	var req proto.GitPushRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, proto.ErrCodeBadRequest, "decode request: "+err.Error())
		return
	}
	current, err := s.gitStore.Get(r.Context(), req.WorkspaceID, req.Entity)
	if err == nil && current.Revision != req.BaseRevision {
		writeJSON(w, http.StatusConflict, proto.GitConflictResponse{
			Entity: req.Entity, ServerRevision: current.Revision, ServerContent: current.Content,
			ServerSignature: current.Signature, ServerActor: current.Actor, ServerUpdatedAt: current.UpdatedAt,
		})
		return
	}
	rec := proto.GitEntity{
		Path:      req.Entity,
		Revision:  proto.GitContentRevision(req.Content),
		Content:   req.Content,
		Signature: req.Signature,
		Actor:     s.actor.String(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := s.gitStore.Put(r.Context(), req.WorkspaceID, rec, req.BaseRevision); err != nil {
		writeError(w, http.StatusInternalServerError, proto.ErrCodeServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, proto.GitPushResponse{Entity: req.Entity, Revision: rec.Revision})
}

func (s *Server) handleAuthChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, proto.ErrCodeBadRequest, "POST only")
		return
	}
	id, ch, err := s.auth.issueChallenge(r.Host)
	if err != nil {
		writeError(w, http.StatusInternalServerError, proto.ErrCodeServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, proto.AuthChallengeResponse{
		ChallengeID: id,
		Nonce:       ch.nonce,
		Hostname:    ch.hostname,
		ExpiresAt:   ch.expiresAt,
	})
}

func (s *Server) handleAuthVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, proto.ErrCodeBadRequest, "POST only")
		return
	}
	var req proto.AuthVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, proto.ErrCodeBadRequest, "decode request: "+err.Error())
		return
	}
	ch, err := s.auth.consumeChallenge(req.ChallengeID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, proto.ErrCodeUnauthorized, err.Error())
		return
	}
	fp, err := identity.ParseFingerprint(req.Fingerprint)
	if err != nil {
		writeError(w, http.StatusUnauthorized, proto.ErrCodeUnauthorized, err.Error())
		return
	}
	pub, ok := s.keystore.Lookup(fp)
	if !ok {
		writeError(w, http.StatusUnauthorized, proto.ErrCodeUnauthorized, "unknown fingerprint")
		return
	}
	canonical, err := json.Marshal(proto.ChallengeSigningInput{
		Version:  proto.AuthSigningVersion,
		Nonce:    ch.nonce,
		Hostname: ch.hostname,
		Scope:    req.Scope,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, proto.ErrCodeServerError, err.Error())
		return
	}
	sig, err := hex.DecodeString(req.Signature)
	if err != nil || !identity.Verify(pub, canonical, sig) {
		writeError(w, http.StatusUnauthorized, proto.ErrCodeUnauthorized, "invalid signature")
		return
	}
	access, expiresAt, err := s.auth.issueToken(fp)
	if err != nil {
		writeError(w, http.StatusInternalServerError, proto.ErrCodeServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, proto.AuthVerifyResponse{AccessToken: access, ExpiresAt: expiresAt})
}

func (s *Server) requireToken(r *http.Request) (identity.Fingerprint, error) {
	hdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(hdr, bearerPrefix) {
		return identity.Fingerprint{}, errors.New("missing bearer token")
	}
	return s.auth.resolveToken(strings.TrimPrefix(hdr, bearerPrefix))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, proto.ErrorResponse{Code: code, Message: message})
}
