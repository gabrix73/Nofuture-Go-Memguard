# Nofuture-Buddy-Go-Memguard
Web application for  ephemeral encryption of texts. Paring the sessions with an interlocutor permets encryption/decryption of conversations via an external realtime communication applications.

Technical Analysis:

<h4>Nofuture Core Security Features:</h4><br>
<ul>
<li>Uses memguard for secure memory management</li>
<li>Implements curve25519 for public-key cryptography</li>
<li>Employs NaCl's box encryption for message security</li>
<li>Utilizes secure session management with random IDs</li>
<li>Implements CORS protection with proper headers</li>
  </ul>
<h4>Key Security Components:</h4>

a) <b>Memory Protection:</b>

<pre>memguard.CatchInterrupt()
defer memguard.Purge()</pre>
<p>This ensures sensitive data is wiped from memory when the program terminates or receives an interrupt signal.</p>

b) <b>Session Management:</b>

<p>Private keys are stored in memguard.LockedBuffer</p>
<p>Public keys are stored as regular bytes</p>
<p>Sessions are managed in a thread-safe sync.Map</p>
<p>Session IDs use cryptographically secure random generation</p>

c) <b>Encryption Process:</b>

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

<h4>RAM-based attacks:</h4>
<ul>
<li>Protected by memguard's secure memory allocation</li>
<li>Keys are automatically wiped from memory</li>
<li>No sensitive data in regular heap memory</li>
<li>Protected against cold boot attacks</li>
  </ul>
<h4>Network-based threats:</h4>
<ul>
<li>All API endpoints use HTTPS</li>
<li>Proper CORS implementation</li>
<li>Input validation on all endpoints</li>
<li>Session-based authentication</li>
  </ul>
<h4>Keylogging protection:</h4>
<ul>
<li>Virtual keyboard bypasses system keyboard</li>
<li>Randomized layout prevents pattern analysis</li>
<li>No physical key events to intercept</li>
<li>Protection against both software and hardware keyloggers</li>
  </ul>
  
<h4>Malware resistance:</h4>
<p>The combination of memguard protection and the virtual keyboard makes it extremely difficult for malware to capture sensitive data because:</p>
Encryption keys are never exposed in regular memory.<br>
Virtual keyboard prevents keylogging, it also uses randomized layouts.<br>
Memory is actively protected against dumping attempts.<br>
<h4>Overall Security Assessment:</h4>
<p>The application provides robust protection against both memory-based attacks and network-based threats.</p> The use of memguard for memory protection, combined with the virtual keyboard's anti-keylogging features, creates multiple layers of security that make it extremely difficult for malware or spyware to capture sensitive data.
