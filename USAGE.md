# 🚀 How to Use nofuture.go

This guide explains how to use `nofuture.go` in practice with a mainstream chat application.

---

## ⚙️ Requirements

- Modern browser (Chrome, Firefox, Brave, etc.)
- JavaScript enabled
- Optional: virtual keyboard enabled for secure passphrase input

---

## 🧪 Step-by-step Example

### 1. Open `nofuture.go` in one browser tab

> Visit: `https://safecomms.virebent.art`

You will see the interface for starting a new secure session.

---

### 2. Open your chat app in another tab

Use any web-based messaging platform:  
- Signal Web  
- Telegram Web  
- WhatsApp Web  
- Email client (optional)

---

### 3. Generate a Session ID

In `nofuture.go`, click **"Generate Session ID"**.  
This creates a **post-quantum key pair**, generates a random nonce, and bundles them into your personal **Session ID**.

You can think of your `Session ID` like a **temporary public key**: it tells the other party how to encrypt messages for you.

---

### 4. Share Your Session ID

Copy your Session ID and paste it into your chat app.  
Send it to your conversation partner. They will import it into their own instance of `nofuture.go`.

> ✅ Session IDs contain **no sensitive private key data** — they are safe to transmit over standard channels.

---

### 5. Synchronize Sessions

This is the **core step**:  
When the other user imports your Session ID, their instance uses it to derive a **shared secret** and bind their session to yours.

🔄 Once both users are synchronized:
- Messages can be encrypted asymmetrically using XChaCha and the shared key
- The session is protected against MITM (with optional signature validation)
- The encrypted messages are now meaningful only to those inside the session

> Without synchronization, decryption will fail.  
> With it, communication is seamless, secure, and ephemeral.

---

### 6. Start exchanging encrypted messages

- You write your message in `nofuture.go`
- It’s encrypted and output as ciphertext
- You copy that into your chat app
- Your contact copies the ciphertext back into their `nofuture.go`, which decrypts it

---

### 7. End Session when done

Once the conversation is finished:

- Click “End Session”
- All keys are destroyed securely in memory
- Even if the ciphertext remains in the chat, it can never be decrypted again

> 💣 Your private key is never written to disk and is irreversibly destroyed.

---

## 🧼 Security Notes

- Session data is stored only in encrypted memory
- `memguard` prevents access even from root processes or dump tools
- Virtual keyboard bypasses system-level keyloggers

---

Enjoy your ephemeral, post-quantum privacy ✊
