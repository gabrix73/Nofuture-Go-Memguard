<strong>Nofuture.go - debian 12 install</strong><br><br>
<strong>Core Components Build Process</strong>
<pre><code>sudo apt-get update && sudo apt-get install -y \
    cmake ninja-build gcc ligit clone --depth 1 https://github.com/open-quantum-safe/liboqs && cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release \
    -DOQS_USE_OPENSSL=ON \
    -DOQS_DIST_BUILD=ON \
    -DOQS_OPTIMIZED_BUILD=ON \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DOQS_BUILD_ONLY_LIB=ON ..bssl-dev libtool autoconf
</code></pre>
<pre><code>ninja
sudo ninja install
sudo ldconfig

# 4. Configurazione Go environment
export CGO_CFLAGS="-O3 -march=native -fstack-protector-strong -D_FORTIFY_SOURCE=2"
export CGO_LDFLAGS="-Wl,-z,relro,-z,now -loqs -lssl -lcrypto"
export GOFLAGS="-buildvcs=false"

# 5. Inizializzazione modulo Go
sudo -u www-data /usr/local/go/bin/go mod init nofuture
sudo -u www-data /usr/local/go/bin/go get -v \
    github.com/awnumar/memguard@v0.22.3 \
    github.com/open-quantum-safe/liboqs-go@latest \
    golang.org/x/crypto@latest \
    golang.org/x/sys@latest</code></pre>
<pre><code>   
# 6. Compilazione finale
sudo -u www-data /usr/local/go/bin/go build -v \
    -tags="oqs,purego,harden" \
    -trimpath \
    -ldflags="-s -w -extldflags '-Wl,-z,relro,-z,now'" \
    -buildmode=pie \
    -o nofuture </code></pre> 
<pre><code>
# 7. Hardening del binario
sudo setcap cap_sys_ptrace,cap_net_admin=ep nofuture
sudo chmod 0711 nofuture    
    </code></pre>
    
<strong>MemGuard Initialization & Configuration:</strong><br>

<pre><code>
        memguard.CatchInterrupt()
        memguard.Purge()
        unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE)</code>
</pre>
<ul>
 <li><strong>Secure Memory Locking:</strong> Prevents swapping sensitive data to disk</li>
<li><strong>Interrupt Handling:</strong> Automatic memory purge on SIGINT/SIGTERM</li>
<li><strong>Deep Memory Purge:</strong> Secure wiping of allocated buffers</li>
        </ul>

<strong>MemGuard in Key Lifecycle Management:</strong><br>
        <pre><code>passphrase, _ := memguard.NewImmutableRandom(32)
defer passphrase.Destroy()</code></pre>
        <ul>
            <li><strong>Immutable Buffers:</strong> Write-protected memory regions</li>
            <li><strong>Ephemeral Storage:</strong> Keys exist only in protected memory</li>
            <li><strong>Automatic Destruction:</strong> Guaranteed wipe with defer</li>
        </ul>

<strong>Enclave-Based Cryptography:</strong><br>
        <pre><code>func deriveEnclaveKey(passphrase *memguard.Enclave) {
    passBuf, _ := passphrase.Open()
    defer passBuf.Destroy()
}</code></pre>
        <ul>
            <li><strong>Double-Layer Protection:</strong> Enclave wrapping + locked buffers</li>
            <li><strong>Controlled Exposure:</strong> Temporary buffer access patterns</li>
            <li><strong>Zero-Copy Architecture:</strong> Minimize memory exposure</li>
        </ul>


<strong>Quantum-Safe Key Exchange:</strong><br>
        <pre><code>pubKey, secKey, _ := quantumKEMKeyPair()
defer pubKey.Destroy()
defer secKey.Destroy()</code></pre>
        <ul>
            <li><strong>MemGuard-Protected Keys:</strong>
                <ul>
                    <li>Public Key: Immutable locked buffer</li>
                    <li>Private Key: Enclave-wrapped storage</li>
                </ul>
            </li>
            <li><strong>Zeroization on Completion:</strong> Guaranteed key destruction</li>
        </ul>

<strong>Secure Session Management:</strong><br>
        <pre><code>type QuantumSession struct {
    sessionKey   *memguard.Enclave
    remotePubKey *memguard.Enclave
}</code></pre>
        <ul>
            <li><strong>Enclave-Wrapped Session Keys:</strong> Encrypted memory storage</li>
            <li><strong>Forward Secrecy:</strong> Ephemeral session keys</li>
            <li><strong>Compartmentalization:</strong> Isolated memory regions per session</li>
        </ul>


<strong>Memory-Hardened Cryptography:</strong><br>
        <pre><code>lockedKey, _ := memguard.NewImmutableFromBytes(key)
defer lockedKey.Destroy()</code></pre>
        <ul>
            <li><strong>Argon2 in Protected Memory:</strong>
                <ul>
                    <li>Memory-hard derivation in locked buffers</li>
                    <li>Secure salt handling</li>
                </ul>
            </li>
            <li><strong>Multi-Layer Protection:</strong>
                <ul>
                    <li>mlock() system calls</li>
                    <li>MADV_DONTDUMP flags</li>
                    <li>Guard pages</li>
                </ul>
            </li>
        </ul>


