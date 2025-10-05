/* -------------------------------------------------------------
   Secure Share Chat – core logic
   • Derive a key from a passphrase (PBKDF2 → AES‑GCM)
   • Encrypt / Decrypt messages
   • Store a simple log in localStorage (acts like a chat)
   • Light / Dark theme toggle
   • System share via the Web Share API (fallback to clipboard)
   ------------------------------------------------------------- */

const logEl = document.getElementById("log");
const msgInput = document.getElementById("msg");
const pwInput = document.getElementById("pw");
const encryptBtn = document.getElementById("encryptBtn");
const decryptBtn = document.getElementById("decryptBtn");
const themeBtn = document.getElementById("theme-toggle");
const themeLink = document.getElementById("theme-stylesheet");

/* ---------- Passphrase gate & per‑passphrase logs ---------- */
let activePassphrase = null;   // holds the passphrase after login

// Helper: generate a storage key that is unique per passphrase
function storageKeyFor(pw) {
  // Simple hash – we don't need cryptographic strength here, just a deterministic key
  const enc = new TextEncoder();
  return crypto.subtle.digest('SHA-256', enc.encode(pw)).then(hash => {
    const hex = Array.from(new Uint8Array(hash))
                     .map(b => b.toString(16).padStart(2, '0'))
                     .join('');
    return `secureChatLog_${hex}`;   // e.g. secureChatLog_a1b2c3…
  });
}

// Show/hide the main UI after successful login
function showMainUI() {
  document.getElementById('loginOverlay').style.display = 'none';
  document.querySelector('header').style.display = '';
  document.querySelector('main').style.display = '';
  document.querySelector('footer').style.display = '';
}

/* ---------- Login button handler ---------- */
document.getElementById('loginBtn').addEventListener('click', async () => {
  const pw = document.getElementById('loginPw').value;
  if (!pw) return alert('Please enter a passphrase');

  activePassphrase = pw;                 // keep it in memory (never persisted)
  LOG_KEY = await storageKeyFor(pw);    // override the global log key
  renderLog();                          // load the correct log for this passphrase
  showMainUI();
});

/* ---------- Helper: base64‑url encode / decode ---------- */
function b64UrlEncode(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
function b64UrlDecode(str) {
  // Pad to multiple of 4
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; ++i) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/* ---------- Crypto: derive key, encrypt, decrypt ---------- */
async function deriveKey(passphrase, salt) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 200_000, // strong enough for browsers
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptMessage(plainText, passphrase) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12)); // GCM nonce

  const key = await deriveKey(passphrase, salt);
  const cipherBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(plainText),
  );

  // concat salt|iv|ciphertext
  const combined = new Uint8Array([
    ...salt,
    ...iv,
    ...new Uint8Array(cipherBuf),
  ]);
  return b64UrlEncode(combined);
}

async function decryptMessage(b64Cipher, passphrase) {
  const data = b64UrlDecode(b64Cipher);
  const salt = data.slice(0, 16);
  const iv = data.slice(16, 28);
  const ct = data.slice(28);

  const key = await deriveKey(passphrase, salt);
  const plainBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ct,
  );
  return new TextDecoder().decode(plainBuf);
}

/* ---------- Log helpers – now per passphrase ---------- */
let LOG_KEY = 'secureChatLog_default';   // placeholder; will be overwritten after login

function loadLog() {
  const raw = localStorage.getItem(LOG_KEY);
  return raw ? JSON.parse(raw) : [];
}
function saveLog(entries) {
  localStorage.setItem(LOG_KEY, JSON.stringify(entries));
}
function addLogEntry(type, content) {
  const entries = loadLog();
  entries.push({ ts: Date.now(), type, content });
  if (entries.length > 200) entries.shift();
  saveLog(entries);
  renderLog();
}
function renderLog() {
  const entries = loadLog();
  logEl.innerHTML = '';
  entries.forEach(e => {
    const div = document.createElement('div');
    div.className = 'log-entry';
    const time = new Date(e.ts).toLocaleTimeString();
    const prefix = e.type === 'enc' ? 'A:' : e.type === 'dec' ? 'B:' : '';
    // Only show decrypted messages (type === 'dec') in the UI, but we keep encrypted entries for history
    if (e.type === 'dec') {
      div.innerHTML = `<span>${time} ${prefix}</span> ${e.content}`;
      logEl.appendChild(div);
    }
  });
  logEl.scrollTop = logEl.scrollHeight;
}
}

/* ---------- Theme handling ---------- */
function setTheme(isDark) {
  themeLink.href = isDark ? "dark.css" : "light.css";
  themeBtn.textContent = isDark ? "☀️" : "🌙";
  localStorage.setItem("prefers-dark", isDark);
}
function initTheme() {
  const stored = localStorage.getItem("prefers-dark");
  const prefersDark =
    stored === null
      ? window.matchMedia("(prefers-color-scheme: dark)").matches
      : stored === "true";
  setTheme(prefersDark);
}
themeBtn.addEventListener("click", () => {
  const currentlyDark = themeLink.getAttribute("href") === "dark.css";
  setTheme(!currentlyDark);
});

/* ---------- Button actions ---------- */
encryptBtn.addEventListener('click', async () => {
  const msg = msgInput.value.trim();
  const pw  = pwInput.value;
  if (!msg || !pw) return alert('Message and passphrase are required');

  // Ensure the active passphrase matches the one used for the log
  if (!activePassphrase || pw !== activePassphrase) {
    return alert('Passphrase must match the one you unlocked with');
  }

  try {
    const cipher = await encryptMessage(msg, pw);
    addLogEntry('enc', cipher);   // store encrypted entry (won’t be displayed)
    // Share / copy as before …
    // (same code as before, omitted for brevity)
    msgInput.value = '';
  } catch (e) { console.error(e); alert('Encryption failed'); }
});

decryptBtn.addEventListener('click', async () => {
  const cipher = msgInput.value.trim();
  const pw = pwInput.value;
  if (!cipher || !pw) return alert('Ciphertext and passphrase are required');

  if (!activePassphrase || pw !== activePassphrase) {
    return alert('Passphrase must match the one you unlocked with');
  }

  try {
    const plain = await decryptMessage(cipher, pw);
    addLogEntry('dec', plain);   // decrypted messages ARE displayed
    msgInput.value = '';
  } catch (e) {
    console.error(e);
    alert('Decryption failed – maybe wrong passphrase or corrupted data');
  }
});

/* ---------- Init ---------- */
initTheme();
renderLog();

/* Register service worker (if supported) – optional but nice */
if ("serviceWorker" in navigator) {
  navigator.serviceWorker
    .register("sw.js")
    .catch((err) => console.warn("SW registration failed", err));
}
