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
<ul>
<li>Private keys are stored in memguard.LockedBuffer</li>
<li>Public keys are stored as regular bytes</li>
<li>Sessions are managed in a thread-safe sync.Map</li>
<li>Session IDs use cryptographically secure random generation</li></ul>

c) <b>Encryption Process:</b>
<ul>
<li>Uses X25519 for key exchange</li>  
<li>mplements box.Seal for authenticated encryption</li>    
<li>Uses random nonces for each encryption</li>  
<li>Zero-copy buffer handling for sensitive data</li>
  </ul>
  
<h4>Virtual Keyboard Security Features:</h4>
<ul>
<li>Randomized key layout on each activation</li>
<li>Right-click secondary character access</li>
<li>Drag-and-drop positioning</li>
<li>Memory-safe input handling</li>
<li>Protection against keyloggers</li>
  </ul>
<b>Security Assessment:</b>

<p>The application provides strong protection against:</p>

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
Virtual keyboard prevents keylogging.<br>
Memory is actively protected against dumping attempts.<br>
<h4>Overall Security Assessment:</h4>
<p>The application provides robust protection against both memory-based attacks and network-based threats.</p> 
<p>The use of memguard for memory protection, combined with the virtual keyboard's anti-keylogging features, creates multiple layers of security that make it extremely difficult for malware or spyware to capture sensitive data.</p>
