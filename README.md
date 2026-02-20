# 🔐 CypherCraft: The Password Guardian

**Privacy-First Password Analyzer & Generator**

---

## 📄 Abstract

CypherCraft: The Password Guardian is a privacy-first web application that empowers users to evaluate the strength of their passwords, check if they've been exposed in known data breaches, and generate cryptographically secure passwords — all without ever storing, logging, or transmitting passwords in plaintext. The application uses the **k-anonymity model** to query the HaveIBeenPwned API, ensuring that even during breach checks, the full password hash is never sent over the network. Built with a Python FastAPI backend serving a modern HTML/Tailwind/JavaScript frontend, the project demonstrates secure coding practices, client-server architecture, and modern web design principles. It is designed as an academic mini project suitable for demonstration in 5–10 minutes.

---

## 🧩 Problem Statement

Users frequently reuse weak passwords across multiple services. Many password-checking tools send passwords to remote servers, creating privacy risks. There is a need for a tool that can assess password strength and check for breaches **without compromising user privacy**.

---

## 💡 Proposed Solution

CypherCraft: The Password Guardian provides three core features in a single, privacy-respecting interface:

1. **Password Analyzer** — Real-time strength analysis using entropy calculations
2. **Breach Checker** — Secure breach detection using k-anonymity
3. **Password Generator** — Cryptographically secure password generation

All processing is designed with privacy as the top priority.

---

## 🔒 How k-Anonymity Works

Instead of sending the user's full password or hash to check for breaches:

1. The password is hashed using **SHA-1**
2. Only the **first 5 characters** of the hash are sent to the HIBP API
3. The API returns all hash suffixes matching that prefix (~500 results)
4. The full hash suffix is compared **locally** on the server
5. The raw password **never leaves the user's browser** in plaintext

This ensures that even if the API were compromised, an attacker cannot determine which specific password was being checked.

---

## 📊 How Entropy & Crack Time Are Calculated

### Entropy

```
Entropy (bits) = Length × log₂(Charset Size)
```

| Characters Used          | Charset Size |
|--------------------------|--------------|
| Lowercase only           | 26           |
| + Uppercase              | 52           |
| + Digits                 | 62           |
| + Symbols                | 94           |

### Crack Time

```
Combinations = 2^Entropy
Crack Time (seconds) = Combinations / Guesses per Second
```

Assumed attack speed: **10 billion guesses per second** (modern GPU cluster).

---

## 🛡️ Security Considerations

| Principle | Implementation |
|-----------|---------------|
| No storage | Passwords are never saved to disk, database, or logs |
| No plaintext transmission | Breach checks use only partial SHA-1 hashes |
| Crypto-secure generation | Uses Python's `secrets` module (backed by `os.urandom`) |
| k-Anonymity | Only 5 chars of hash prefix sent to HIBP API |
| No client-side persistence | No localStorage/sessionStorage/cookies for passwords |
| Clipboard auto-clear | Copied passwords are cleared after 30 seconds |

---

## ⚙️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.10+, FastAPI, Uvicorn |
| Frontend | HTML5, Tailwind CSS (CDN), Vanilla JavaScript |
| Breach API | HaveIBeenPwned (k-anonymity range endpoint) |
| HTTP Client | httpx (async) |
| Security | hashlib (SHA-1), secrets (CSPRNG) |

---

## 🚀 Setup & Run

### Prerequisites

- Python 3.10 or higher
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/CypherCraft.git
cd CypherCraft

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

The app will start at **http://localhost:8001**

### Alternative: Using Uvicorn directly

```bash
uvicorn app:app --host 0.0.0.0 --port 8001 --reload
```

---

## 🧪 Testing

### Sample Test Passwords

| Password | Expected Strength | Expected Breach |
|----------|-------------------|-----------------|
| `123` | Very Weak | Yes |
| `password` | Very Weak | Yes (millions) |
| `Hello123` | Moderate | Possibly |
| `Tr0ub4dor&3` | Strong | Possibly |
| `k8$Qm!zP#xL9@wR` | Very Strong | Unlikely |

### Edge Cases

- Empty input → Analyzer shows zeroed stats
- Single character → Very Weak strength
- Breach check with no internet → Graceful error message
- Generator with all options unchecked → Error handling

### Verifying Breach Check

1. Type `password` → Should show "Found in X breaches" (red)
2. Type a long random string → Should show "No known breaches" (green)
3. Disconnect internet → Should show network error (yellow)

---

## 📁 Project Structure

```
CypherCraft/
├── app.py                 # FastAPI backend entry point
├── requirements.txt       # Python dependencies
├── utils/
│   ├── __init__.py
│   ├── hash_utils.py      # SHA-1 hashing + HIBP breach check
│   ├── entropy.py         # Entropy calculation + crack time
│   └── generator.py       # Secure password generation
├── templates/
│   └── index.html         # Frontend HTML (Tailwind + JS)
├── static/
│   ├── style.css          # Custom styles & animations
│   └── script.js          # Client-side logic
└── README.md              # This file
```

---

## ⚠️ Limitations

- Breach check requires internet connectivity
- Strength analysis uses basic entropy (does not account for dictionary attacks or patterns)
- Word list for passphrases is limited (~120 words)
- No offline mode
- No multi-language support

---

## 🔮 Future Enhancements

- **AI-powered password suggestions** — ML model to suggest stronger variants
- **Offline mode** — Service worker for breach checking with cached data
- **Password manager integration** — Export generated passwords
- **Multi-language UI** — Internationalization support
- **Advanced pattern detection** — Dictionary attack simulation
- **Browser extension** — Check passwords directly in login forms

---

## 📜 License

This project is open-source under the MIT License.

---
