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

### 3. Click “Generate Session ID” in nofuture.go

This creates a secure post-quantum key pair and generates your session metadata.

---

### 4. Copy your Session ID and share it with your contact

Paste it in your chat tab and send it to your conversation partner.

> 🔐 The session ID contains no sensitive information and can be safely sent in cleartext.

---

### 5. Your contact pastes your Session ID into their `nofuture.go`

Once both ends are synced, the encryption tunnel is live.

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
