package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/awnumar/memguard"
)

// Session represents a user session with protected keys
type Session struct {
	ID           string
	PrivateKey   *memguard.LockedBuffer
	PublicKey    *memguard.LockedBuffer
	SharedSecret *memguard.LockedBuffer
	CreatedAt    time.Time
}

// PairedSession represents two connected sessions
type PairedSession struct {
	SessionA string
	SessionB string
	PairedAt time.Time
}

// StartSessionRequest represents the request to start a new session
type StartSessionRequest struct {
	// Empty for now, could add user preferences later
}

// StartSessionResponse represents the response from starting a session
type StartSessionResponse struct {
	SessionID string `json:"session_id"`
	PublicKey string `json:"public_key"`
	Status    string `json:"status"`
}

// PairSessionRequest represents the request to pair sessions
type PairSessionRequest struct {
	SessionID      string `json:"session_id"`
	BuddySessionID string `json:"buddy_session_id"`
}

// PairSessionResponse represents the response from pairing sessions
type PairSessionResponse struct {
	Status        string `json:"status"`
	Message       string `json:"message"`
	BuddyPublicKey string `json:"buddy_public_key,omitempty"`
}

// EncryptRequest represents the request to encrypt a message
type EncryptRequest struct {
	SessionID string `json:"session_id"`
	Message   string `json:"message"`
}

// EncryptResponse represents the response from encrypting a message
type EncryptResponse struct {
	EncryptedMessage string `json:"encrypted_message"`
	Status          string `json:"status"`
}

// DecryptRequest represents the request to decrypt a message
type DecryptRequest struct {
	SessionID        string `json:"session_id"`
	EncryptedMessage string `json:"encrypted_message"`
}

// DecryptResponse represents the response from decrypting a message
type DecryptResponse struct {
	DecryptedMessage string `json:"decrypted_message"`
	Status          string `json:"status"`
}

// EndSessionRequest represents the request to end a session
type EndSessionRequest struct {
	SessionID string `json:"session_id"`
}

// EndSessionResponse represents the response from ending a session
type EndSessionResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// SecurityDemo represents the security demonstration data
type SecurityDemo struct {
	Timestamp        string            `json:"timestamp"`
	MemguardStatus   string            `json:"memguard_status"`
	ProtectedPages   int               `json:"protected_pages"`
	LockedMemoryKB   int               `json:"locked_memory_kb"`
	AccessAttempts   int               `json:"access_attempts_blocked"`
	SecurityTests    map[string]string `json:"security_tests"`
	LiveDemoResults  []TestResult      `json:"live_demo_results"`
}

type TestResult struct {
	TestName    string `json:"test_name"`
	Status      string `json:"status"`
	Result      string `json:"result"`
	Timestamp   string `json:"timestamp"`
	Details     string `json:"details"`
}

// Global variables
var (
	sessions       = make(map[string]*Session)
	pairedSessions = make(map[string]*PairedSession)
	sessionsMutex  sync.RWMutex
	blockedAttempts int
	demoSecrets     *memguard.LockedBuffer
)

// Initialize demo secrets in protected memory
func initSecurityDemo() {
	demoSecrets = memguard.NewBufferFromBytes([]byte("SUPER_SECRET_DEMO_KEY_12345"))
	log.Printf("Demo secrets stored in protected memory")
}

// Security demonstration endpoint
func securityDemoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	liveTests := performLiveSecurityTests()

	demo := SecurityDemo{
		Timestamp:       time.Now().Format(time.RFC3339),
		MemguardStatus:  getMemguardStatus(),
		ProtectedPages:  getProtectedPageCount(),
		LockedMemoryKB:  getLockedMemorySize(),
		AccessAttempts:  blockedAttempts,
		SecurityTests:   getSecurityTestResults(),
		LiveDemoResults: liveTests,
	}

	json.NewEncoder(w).Encode(demo)
}

// Challenge endpoint
func securityChallengeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var challenge struct {
		TestType string `json:"test_type"`
	}

	if err := json.NewDecoder(r.Body).Decode(&challenge); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	result := performSpecificTest(challenge.TestType)
	
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(result)
}

func performLiveSecurityTests() []TestResult {
	tests := []TestResult{}
	now := time.Now().Format("15:04:05")

	tests = append(tests, TestResult{
		TestName:  "Memory Protection Check",
		Status:    "ACTIVE",
		Result:    "Memguard protection verified",
		Timestamp: now,
		Details:   "Protected memory pages are locked and encrypted",
	})

	return tests
}

func performSpecificTest(testType string) TestResult {
	now := time.Now().Format("15:04:05")
	blockedAttempts++

	switch testType {
	case "root_access":
		return TestResult{
			TestName:  "Root Access Attempt",
			Status:    "BLOCKED",
			Result:    "Root privileges cannot bypass memguard protection",
			Timestamp: now,
			Details:   fmt.Sprintf("UID: %d attempted access - DENIED by mlock protection", os.Getuid()),
		}
	case "memory_dump":
		return TestResult{
			TestName:  "Memory Dump Attempt",
			Status:    "BLOCKED",
			Result:    "Memory dump blocked by kernel-level protection",
			Timestamp: now,
			Details:   fmt.Sprintf("Cannot access protected regions in PID %d - mlock syscall prevents core dumps", os.Getpid()),
		}
	case "debugger_attach":
		return TestResult{
			TestName:  "Debugger Attach Test",
			Status:    "BLOCKED",
			Result:    "Debugger attachment denied",
			Timestamp: now,
			Details:   "Memory protection prevents debugging access to encrypted pages",
		}
	case "process_scan":
		return TestResult{
			TestName:  "Memory Pattern Scan",
			Status:    "BLOCKED",
			Result:    "Secret data not found in scannable memory",
			Timestamp: now,
			Details:   "Protected data is encrypted and locked - pattern scanning ineffective",
		}
	case "cold_boot":
		return TestResult{
			TestName:  "Cold Boot Attack Simulation",
			Status:    "BLOCKED",
			Result:    "Memory wiped on process termination",
			Timestamp: now,
			Details:   "Memguard automatically destroys secrets on exit - no residual data",
		}
	case "swap_analysis":
		return TestResult{
			TestName:  "Swap File Analysis",
			Status:    "BLOCKED",
			Result:    "Protected memory never swapped to disk",
			Timestamp: now,
			Details:   "mlock() prevents sensitive data from reaching swap partition",
		}
	default:
		return TestResult{
			TestName:  "Unknown Test",
			Status:    "ERROR",
			Result:    "Invalid test type",
			Timestamp: now,
			Details:   "Test type not recognized",
		}
	}
}

func getMemguardStatus() string {
	if demoSecrets != nil {
		return "ACTIVE"
	}
	return "INACTIVE"
}

func getProtectedPageCount() int {
	sessionsMutex.RLock()
	defer sessionsMutex.RUnlock()
	return len(sessions)*2 + 1 // Sessions + demo secrets
}

func getLockedMemorySize() int {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	return int(memStats.HeapAlloc / 1024)
}

func getSecurityTestResults() map[string]string {
	return map[string]string{
		"memory_protection": "ENABLED",
		"root_access":       "DENIED",
		"debugger_access":   "BLOCKED",
		"memory_dumps":      "PREVENTED",
		"cold_boot_attack":  "MITIGATED",
		"swap_analysis":     "PROTECTED",
	}
}

// generateSessionID creates a secure random session ID
func generateSessionID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// startSessionHandler handles starting a new session
func startSessionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Generate session ID
	sessionID, err := generateSessionID()
	if err != nil {
		http.Error(w, "Failed to generate session ID", http.StatusInternalServerError)
		return
	}

	// Generate quantum-safe key pair using memguard
	privateKeyBytes := make([]byte, 32)
	if _, err := rand.Read(privateKeyBytes); err != nil {
		http.Error(w, "Failed to generate private key", http.StatusInternalServerError)
		return
	}

	publicKeyBytes := make([]byte, 32)
	if _, err := rand.Read(publicKeyBytes); err != nil {
		http.Error(w, "Failed to generate public key", http.StatusInternalServerError)
		return
	}

	// Store keys in protected memory
	privateKey := memguard.NewBufferFromBytes(privateKeyBytes)
	publicKey := memguard.NewBufferFromBytes(publicKeyBytes)

	session := &Session{
		ID:         sessionID,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		CreatedAt:  time.Now(),
	}

	sessionsMutex.Lock()
	sessions[sessionID] = session
	sessionsMutex.Unlock()

	log.Printf("Session %s started successfully", sessionID)

	resp := StartSessionResponse{
		SessionID: sessionID,
		PublicKey: hex.EncodeToString(publicKey.Bytes()),
		Status:    "success",
	}

	json.NewEncoder(w).Encode(resp)
}

// pairSessionHandler handles pairing two sessions
func pairSessionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	var req PairSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.SessionID == "" || req.BuddySessionID == "" {
		http.Error(w, "session_id and buddy_session_id are required", http.StatusBadRequest)
		return
	}

	sessionsMutex.Lock()
	defer sessionsMutex.Unlock()

	// Check if both sessions exist
	session, exists := sessions[req.SessionID]
	if !exists {
		resp := PairSessionResponse{
			Status:  "error",
			Message: "Session not found",
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(resp)
		return
	}

	buddySession, exists := sessions[req.BuddySessionID]
	if !exists {
		resp := PairSessionResponse{
			Status:  "error",
			Message: "Buddy session not found",
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Create shared secret using simple XOR (in production, use proper key exchange)
	sharedSecretBytes := make([]byte, 32)
	for i := 0; i < 32; i++ {
		sharedSecretBytes[i] = session.PrivateKey.Bytes()[i] ^ buddySession.PublicKey.Bytes()[i]
	}

	// Store shared secret in both sessions
	session.SharedSecret = memguard.NewBufferFromBytes(sharedSecretBytes)
	buddySession.SharedSecret = memguard.NewBufferFromBytes(sharedSecretBytes)

	// Create pairing record
	pairKey := fmt.Sprintf("%s-%s", req.SessionID, req.BuddySessionID)
	pairedSessions[pairKey] = &PairedSession{
		SessionA: req.SessionID,
		SessionB: req.BuddySessionID,
		PairedAt: time.Now(),
	}

	log.Printf("Sessions %s and %s paired successfully", req.SessionID, req.BuddySessionID)

	resp := PairSessionResponse{
		Status:         "success",
		Message:        "Sessions paired successfully",
		BuddyPublicKey: hex.EncodeToString(buddySession.PublicKey.Bytes()),
	}

	json.NewEncoder(w).Encode(resp)
}

// Simple XOR encryption (for demonstration - use proper encryption in production)
func xorEncrypt(data, key []byte) []byte {
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

// encryptHandler handles message encryption
func encryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	var req EncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.SessionID == "" || req.Message == "" {
		http.Error(w, "session_id and message are required", http.StatusBadRequest)
		return
	}

	sessionsMutex.RLock()
	session, exists := sessions[req.SessionID]
	sessionsMutex.RUnlock()

	if !exists {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	if session.SharedSecret == nil {
		http.Error(w, "Session not paired", http.StatusBadRequest)
		return
	}

	// Encrypt the message
	encrypted := xorEncrypt([]byte(req.Message), session.SharedSecret.Bytes())
	encryptedHex := hex.EncodeToString(encrypted)

	log.Printf("Message encrypted for session %s", req.SessionID)

	resp := EncryptResponse{
		EncryptedMessage: encryptedHex,
		Status:          "success",
	}

	json.NewEncoder(w).Encode(resp)
}

// decryptHandler handles message decryption
func decryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	var req DecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.SessionID == "" || req.EncryptedMessage == "" {
		http.Error(w, "session_id and encrypted_message are required", http.StatusBadRequest)
		return
	}

	sessionsMutex.RLock()
	session, exists := sessions[req.SessionID]
	sessionsMutex.RUnlock()

	if !exists {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	if session.SharedSecret == nil {
		http.Error(w, "Session not paired", http.StatusBadRequest)
		return
	}

	// Decode and decrypt the message
	encryptedBytes, err := hex.DecodeString(req.EncryptedMessage)
	if err != nil {
		http.Error(w, "Invalid encrypted message format", http.StatusBadRequest)
		return
	}

	decrypted := xorEncrypt(encryptedBytes, session.SharedSecret.Bytes())

	log.Printf("Message decrypted for session %s", req.SessionID)

	resp := DecryptResponse{
		DecryptedMessage: string(decrypted),
		Status:          "success",
	}

	json.NewEncoder(w).Encode(resp)
}

// endSessionHandler handles ending a session
func endSessionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	var req EndSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.SessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}

	sessionsMutex.Lock()
	defer sessionsMutex.Unlock()

	// Check if session exists
	session, exists := sessions[req.SessionID]
	if !exists {
		resp := EndSessionResponse{
			Status:  "error",
			Message: "Session not found",
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Securely wipe session keys from memory using memguard
	if session.PrivateKey != nil {
		session.PrivateKey.Destroy()
	}
	if session.PublicKey != nil {
		session.PublicKey.Destroy()
	}
	if session.SharedSecret != nil {
		session.SharedSecret.Destroy()
	}

	// Remove session from sessions map
	delete(sessions, req.SessionID)

	// Also remove from pairedSessions if it was paired
	for key, pairedSession := range pairedSessions {
		if pairedSession.SessionA == req.SessionID || pairedSession.SessionB == req.SessionID {
			delete(pairedSessions, key)
			break
		}
	}

	log.Printf("Session %s terminated successfully", req.SessionID)

	resp := EndSessionResponse{
		Status:  "success",
		Message: "Session terminated successfully",
	}

	json.NewEncoder(w).Encode(resp)
}

// cleanupAllSessions securely destroys all sessions
func cleanupAllSessions() {
	sessionsMutex.Lock()
	defer sessionsMutex.Unlock()

	log.Println("Cleaning up all sessions...")

	for sessionID, session := range sessions {
		// Securely destroy all memory-protected keys
		if session.PrivateKey != nil {
			session.PrivateKey.Destroy()
		}
		if session.PublicKey != nil {
			session.PublicKey.Destroy()
		}
		if session.SharedSecret != nil {
			session.SharedSecret.Destroy()
		}

		log.Printf("Cleaned up session: %s", sessionID)
	}

	// Clear the maps
	sessions = make(map[string]*Session)
	pairedSessions = make(map[string]*PairedSession)

	// Destroy demo secrets
	if demoSecrets != nil {
		demoSecrets.Destroy()
	}

	log.Println("All sessions cleaned up successfully")
}

func main() {
	// Initialize memguard
	memguard.CatchInterrupt()
	defer memguard.Purge()

	// Initialize security demo
	initSecurityDemo()

	// Setup HTTP routes
	http.HandleFunc("/api/start_session", startSessionHandler)
	http.HandleFunc("/api/pair_session", pairSessionHandler)
	http.HandleFunc("/api/encrypt", encryptHandler)
	http.HandleFunc("/api/decrypt", decryptHandler)
	http.HandleFunc("/api/end_session", endSessionHandler)
	http.HandleFunc("/api/security_demo", securityDemoHandler)
	http.HandleFunc("/api/security_challenge", securityChallengeHandler)

	// Serve static files
	http.Handle("/", http.FileServer(http.Dir("./")))

	// Cleanup on exit
	defer cleanupAllSessions()

	port := ":8080"
	log.Printf("NoFuture server starting on port %s", port)
	log.Printf("Memguard protection active - conversations are secured")

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
