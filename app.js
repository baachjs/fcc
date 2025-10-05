/* -------------------------------------------------------------
   Secure Share Chat – updated for “conversation selector”
   ------------------------------------------------------------- */

const logEl      = document.getElementById('log');
const msgInput   = document.getElementById('msg');
const pwInput    = document.getElementById('pw');
const encryptBtn = document.getElementById('encryptBtn');
const decryptBtn = document.getElementById('decryptBtn');
const themeBtn   = document.getElementById('theme-toggle');
const logoutBtn  = document.getElementById('logoutBtn');   // <-- NEW
const themeLink  = document.getElementById('theme-stylesheet');

/* ---------- Helper: base64‑url encode / decode ---------- */
function b64UrlEncode(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
           .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/,'');
}
function b64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; ++i) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/* ---------- Crypto (unchanged) ---------- */
async function deriveKey(passphrase, salt) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 200_000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt','decrypt']
  );
}
async function encryptMessage(plainText, passphrase) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt);
  const cipherBuf = await crypto.subtle.encrypt({name:'AES-GCM',iv}, key, enc.encode(plainText));
  const combined = new Uint8Array([...salt,...iv,...new Uint8Array(cipherBuf)]);
  return b64UrlEncode(combined);
}
async function decryptMessage(b64Cipher, passphrase) {
  const data = b64UrlDecode(b64Cipher);
  const salt = data.slice(0,16);
  const iv   = data.slice(16,28);
  const ct   = data.slice(28);
  const key = await deriveKey(passphrase, salt);
  const plainBuf = await crypto.subtle.decrypt({name:'AES-GCM',iv}, key, ct);
  return new TextDecoder().decode(plainBuf);
}

/* ---------- Conversation selector (passphrase gate) ---------- */
let activePassphrase = null;   // Holds the passphrase for the current session
let LOG_KEY = 'secureChatLog_default'; // Will be replaced after login

/** Generate a deterministic storage key from the passphrase (SHA‑256 → hex) **/
async function storageKeyFor(pw) {
  const enc = new TextEncoder();
  const hash = await crypto.subtle.digest('SHA-256', enc.encode(pw));
  const hex = Array.from(new Uint8Array(hash))
                   .map(b => b.toString(16).padStart(2,'0')).join('');
  return `secureChatLog_${hex}`;
}

/** Show the main UI after a passphrase has been entered **/
function showMainUI() {
  document.getElementById('loginOverlay').style.display = 'none';
  document.querySelector('header').style.display = '';
  document.querySelector('main').style.display = '';
  document.querySelector('footer').style.display = '';
}

/** Hide the UI and go back to the login screen (logout) **/
function logout() {
  activePassphrase = null;
  LOG_KEY = 'secureChatLog_default';
  document.getElementById('loginOverlay').style.display = 'flex';
  document.querySelector('header').style.display = 'none';
  document.querySelector('main').style.display = 'none';
  document.querySelector('footer').style.display = 'none';
  // clear the visible log (optional)
  logEl.innerHTML = '';
}

/* ---------- Login button handler ----------
   User types a passphrase → we compute a unique LOG_KEY,
   load that conversation’s history, and reveal the UI. */
document.getElementById('loginBtn').addEventListener('click', async () => {
  const pw = document.getElementById('loginPw').value;
  if (!pw) return alert('Please enter a passphrase');

  activePassphrase = pw;                     // keep it in memory only
  LOG_KEY = await storageKeyFor(pw);         // unique key per conversation
  renderLog();                               // load that conversation’s log
  showMainUI();
});

/* ---------- Logout button ----------
   Allows you to switch to a different conversation. */
logoutBtn.addEventListener('click', logout);

/* ---------- Log helpers – per‑conversation ---------- */
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
    // Only show decrypted messages (type === 'dec')
    if (e.type === 'dec') {
      const div = document.createElement('div');
      div.className = 'log-entry';
      const time = new Date(e.ts).toLocaleTimeString();
      const prefix = e.type === 'enc' ? 'A:' : e.type === 'dec' ? 'B:' : '';
      div.innerHTML = `<span>${time} ${prefix}</span> ${e.content}`;
      logEl.appendChild(div);
    }
  });
  logEl.scrollTop = logEl.scrollHeight;
}

/* ---------- Encrypt / Decrypt button handlers ----------
   They now **always** use the passphrase that was entered at login.
   No extra validation is needed. */
encryptBtn.addEventListener('click', async () => {
  const msg = msgInput.value.trim();
  const pw  = pwInput.value;   // optional second field – keep for UI consistency
  if (!msg) return alert('Message cannot be empty');
  if (!activePassphrase) return alert('You must be logged in first');

  try {
    const cipher = await encryptMessage(msg, activePassphrase);
    addLogEntry('enc', cipher);   // stored but not shown
    // ----- Share / copy (unchanged) -----
    if (navigator.canShare && navigator.share) {
      try {
        await navigator.share({title:'Encrypted Message',text:cipher});
      } catch (_) {/* user cancelled */}
    } else if (navigator.clipboard) {
      await navigator.clipboard.writeText(cipher);
      alert('Cipher copied to clipboard');
    }
    msgInput.value = '';
  } catch (e) {
    console.error(e);
    alert('Encryption failed');
  }
});

decryptBtn.addEventListener('click', async () => {
  const cipher = msgInput.value.trim();
  if (!cipher) return alert('Paste a ciphertext to decrypt');
  if (!activePassphrase) return alert('You must be logged in first');

  try {
    const plain = await decryptMessage(cipher, activePassphrase);
    addLogEntry('dec', plain);   // visible in the log with “B:”
    msgInput.value = '';
  } catch (e) {
    console.error(e);
    alert('Decryption failed – maybe wrong passphrase or corrupted data');
  }
});

/* ---------- Theme handling (unchanged) ---------- */
themeBtn.addEventListener('click', () => {
  const currentlyDark = themeLink.getAttribute('href') === 'dark.css';
  setTheme(!currentlyDark);
});
initTheme();

/* ---------- Service‑worker registration (unchanged) ---------- */
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js')
    .catch(err => console.warn('SW registration failed', err));
}
