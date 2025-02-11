# Nofuture-Buddy-Go-Memguard
Web application for  ephemeral encryption of texts. Paring the sessions with an interlocutor permets encryption/decryption of conversations via an external realtime communication applications.

Technical Analysis:

Nofuture Core Security Features:
Uses memguard for secure memory management
Implements curve25519 for public-key cryptography
Employs NaCl's box encryption for message security
Utilizes secure session management with random IDs
Implements CORS protection with proper headers
Key Security Components:

a) Memory Protection:

memguard.CatchInterrupt()
defer memguard.Purge()
This ensures sensitive data is wiped from memory when the program terminates or receives an interrupt signal.

b) Session Management:

Private keys are stored in memguard.LockedBuffer
Public keys are stored as regular bytes
Sessions are managed in a thread-safe sync.Map
Session IDs use cryptographically secure random generation
c) Encryption Process:

Uses X25519 for key exchange
Implements box.Seal for authenticated encryption
Uses random nonces for each encryption
Zero-copy buffer handling for sensitive data
Virtual Keyboard Security Features:
Randomized key layout on each activation
Right-click secondary character access
Drag-and-drop positioning
Memory-safe input handling
Protection against keyloggers
Security Assessment:

The application provides strong protection against:

RAM-based attacks:
Protected by memguard's secure memory allocation
Keys are automatically wiped from memory
No sensitive data in regular heap memory
Protected against cold boot attacks
Network-based threats:
All API endpoints use HTTPS
Proper CORS implementation
Input validation on all endpoints
Session-based authentication
Keylogging protection:
Virtual keyboard bypasses system keyboard
Randomized layout prevents pattern analysis
No physical key events to intercept
Protection against both software and hardware keyloggers
Malware resistance:
The combination of memguard protection and the virtual keyboard makes it extremely difficult for malware to capture sensitive data because:
Encryption keys are never exposed in regular memory
Virtual keyboard prevents keylogging
Screen recording is ineffective due to randomized layouts
Memory is actively protected against dumping attempts
Overall Security Assessment:
The application provides robust protection against both memory-based attacks and network-based threats. The use of memguard for memory protection, combined with the virtual keyboard's anti-keylogging features, creates multiple layers of security that make it extremely difficult for malware or spyware to capture sensitive data.
