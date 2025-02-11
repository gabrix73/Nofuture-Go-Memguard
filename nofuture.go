package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"strings"
	"sync"

	"github.com/awnumar/memguard"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

type Session struct {
	PrivateKey     *memguard.LockedBuffer
	PublicKey      *memguard.LockedBuffer
	BuddyPublicKey *memguard.LockedBuffer
}

var (
	sessions sync.Map
)

const (
	nonceLength = 24
	keyLength   = 32
)

func init() {
	memguard.CatchInterrupt()
	runtime.GC()
}

func generateKeyPair() (*memguard.LockedBuffer, *memguard.LockedBuffer, error) {
	privateKeyBuf := memguard.NewBuffer(keyLength)
	defer privateKeyBuf.Destroy()

	if _, err := rand.Read(privateKeyBuf.Bytes()); err != nil {
		return nil, nil, fmt.Errorf("key generation failed: %w", err)
	}

	publicKeyBuf := memguard.NewBuffer(keyLength)
	defer publicKeyBuf.Destroy()

	publicKey, err := curve25519.X25519(privateKeyBuf.Bytes(), curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("public key derivation failed: %w", err)
	}

	privateKeyLocked := memguard.NewBuffer(keyLength)
	publicKeyLocked := memguard.NewBuffer(keyLength)

	copy(privateKeyLocked.Bytes(), privateKeyBuf.Bytes())
	copy(publicKeyLocked.Bytes(), publicKey)

	return privateKeyLocked, publicKeyLocked, nil
}

func startSession(c *gin.Context) {
	c.Header("Content-Type", "application/json")
	log.Printf("Starting new secure session...")

	privateKey, publicKey, err := generateKeyPair()
	if err != nil {
		log.Printf("Error generating key pair: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	sessionIDBuf := memguard.NewBuffer(12)
	if _, err := rand.Read(sessionIDBuf.Bytes()); err != nil {
		log.Printf("Error generating session ID: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate session ID"})
		return
	}
	defer sessionIDBuf.Destroy()

	sessionID := base64.RawURLEncoding.EncodeToString(sessionIDBuf.Bytes())

	sessions.Store(sessionID, &Session{
		PrivateKey:     privateKey,
		PublicKey:      publicKey,
		BuddyPublicKey: nil,
	})

	log.Printf("Session created successfully: %s", sessionID)

	c.JSON(http.StatusOK, gin.H{
		"session_id": sessionID,
		"public_key": base64.StdEncoding.EncodeToString(publicKey.Bytes()),
	})

	runtime.GC()
}

func endSession(c *gin.Context) {
	c.Header("Content-Type", "application/json")
	var req struct {
		SessionID string `json:"session_id" binding:"required"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if sess, loaded := sessions.LoadAndDelete(req.SessionID); loaded {
		session := sess.(*Session)
		if session.PrivateKey != nil {
			session.PrivateKey.Destroy()
		}
		if session.PublicKey != nil {
			session.PublicKey.Destroy()
		}
		if session.BuddyPublicKey != nil {
			session.BuddyPublicKey.Destroy()
		}
	}

	log.Printf("Session ended and cleaned up: %s", req.SessionID)
	c.JSON(http.StatusOK, gin.H{"status": "session_ended"})

	runtime.GC()
}

func pairSessions(c *gin.Context) {
	c.Header("Content-Type", "application/json")
	var req struct {
		SessionIDA string `json:"session_id_A" binding:"required"`
		SessionIDB string `json:"session_id_B" binding:"required"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	sessionA, ok := sessions.Load(req.SessionIDA)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "session A not found"})
		return
	}

	sessionB, ok := sessions.Load(req.SessionIDB)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "session B not found"})
		return
	}

	sessA := sessionA.(*Session)
	sessB := sessionB.(*Session)

	sessA.BuddyPublicKey = memguard.NewBuffer(keyLength)
	sessB.BuddyPublicKey = memguard.NewBuffer(keyLength)

	copy(sessA.BuddyPublicKey.Bytes(), sessB.PublicKey.Bytes())
	copy(sessB.BuddyPublicKey.Bytes(), sessA.PublicKey.Bytes())

	log.Printf("Sessions paired: %s with %s", req.SessionIDA, req.SessionIDB)
	c.JSON(http.StatusOK, gin.H{
		"status":       "paired",
		"session_id_A": req.SessionIDA,
		"session_id_B": req.SessionIDB,
	})

	runtime.GC()
}

func buddyEncrypt(c *gin.Context) {
	c.Header("Content-Type", "application/json")
	var req struct {
		SessionID string `json:"session_id" binding:"required"`
		Plaintext string `json:"plaintext" binding:"required"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	session, ok := sessions.Load(req.SessionID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}

	sess := session.(*Session)
	if sess.BuddyPublicKey == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session not paired"})
		return
	}

	privateKeyArray := memguard.NewBuffer(keyLength)
	buddyPubArray := memguard.NewBuffer(keyLength)
	defer privateKeyArray.Destroy()
	defer buddyPubArray.Destroy()

	copy(privateKeyArray.Bytes(), sess.PrivateKey.Bytes())
	copy(buddyPubArray.Bytes(), sess.BuddyPublicKey.Bytes())

	nonceBuf := memguard.NewBuffer(nonceLength)
	defer nonceBuf.Destroy()

	if _, err := rand.Read(nonceBuf.Bytes()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "nonce generation failed"})
		return
	}

	var nonce [nonceLength]byte
	copy(nonce[:], nonceBuf.Bytes())

	var privateKeyArr, buddyPubArr [keyLength]byte
	copy(privateKeyArr[:], privateKeyArray.Bytes())
	copy(buddyPubArr[:], buddyPubArray.Bytes())

	plaintextBuf := memguard.NewBufferFromBytes([]byte(req.Plaintext))
	defer plaintextBuf.Destroy()

	encrypted := box.Seal(nonce[:], plaintextBuf.Bytes(), &nonce, &buddyPubArr, &privateKeyArr)

	c.JSON(http.StatusOK, gin.H{
		"encrypted_b64": base64.StdEncoding.EncodeToString(encrypted),
	})

	runtime.GC()
}

func buddyDecrypt(c *gin.Context) {
	c.Header("Content-Type", "application/json")
	var req struct {
		SessionID     string `json:"session_id" binding:"required"`
		EncryptedB64 string `json:"encrypted_b64" binding:"required"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	session, ok := sessions.Load(req.SessionID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}

	sess := session.(*Session)
	if sess.BuddyPublicKey == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session not paired"})
		return
	}

	encrypted, err := base64.StdEncoding.DecodeString(req.EncryptedB64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid base64 encoding"})
		return
	}

	if len(encrypted) < nonceLength {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ciphertext length"})
		return
	}

	privateKeyArray := memguard.NewBuffer(keyLength)
	buddyPubArray := memguard.NewBuffer(keyLength)
	defer privateKeyArray.Destroy()
	defer buddyPubArray.Destroy()

	copy(privateKeyArray.Bytes(), sess.PrivateKey.Bytes())
	copy(buddyPubArray.Bytes(), sess.BuddyPublicKey.Bytes())

	var privateKeyArr, buddyPubArr [keyLength]byte
	var nonce [nonceLength]byte
	copy(privateKeyArr[:], privateKeyArray.Bytes())
	copy(buddyPubArr[:], buddyPubArray.Bytes())
	copy(nonce[:], encrypted[:nonceLength])

	decrypted, ok := box.Open(nil, encrypted[nonceLength:], &nonce, &buddyPubArr, &privateKeyArr)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "decryption failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"plaintext": string(decrypted)})
	runtime.GC()
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func main() {
	memguard.CatchInterrupt()
	defer memguard.Purge()

	log.Printf("Starting Nofuture server with enhanced memory protection...")

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	// CORS middleware only for API routes
	r.Use(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.Header("Access-Control-Allow-Origin", "*")
			c.Header("Access-Control-Allow-Methods", "POST, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Content-Type")
			c.Header("Content-Type", "application/json")

			if c.Request.Method == "OPTIONS" {
				c.AbortWithStatus(204)
				return
			}
		}
		c.Next()
	})

	// Create API group with its own middleware
	api := r.Group("/api")
	{
		api.POST("/start_session", startSession)
		api.POST("/end_session", endSession)
		api.POST("/pair_sessions", pairSessions)
		api.POST("/buddy_encrypt", buddyEncrypt)
		api.POST("/buddy_decrypt", buddyDecrypt)
	}

	// Serve static files
	r.StaticFile("/", "./index.html")
	r.Static("/js", "./js")
	r.Static("/static", "./static")

	serverAddr := "127.0.0.1:3000"
	log.Printf("Server starting on %s", serverAddr)

	if err := r.Run(serverAddr); err != nil {
		log.Fatalf("Server startup failed: %v", err)
	}
}
