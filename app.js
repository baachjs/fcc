/* ============================================================
   Secure Share Chat – single‑theme version with your colour spec
   ============================================================ */

const logEl      = document.getElementById('log');
const msgInput   = document.getElementById('msg');
const hiddenPw   = document.getElementById('hiddenPw');   // hidden field
const encryptBtn = document.getElementById('encryptBtn');
const decryptBtn = document.getElementById('decryptBtn');
const loginBtn   = document.getElementById('loginBtn');
const loginPw   = document.getElementById('loginPw');
const backBtn    = document.getElementById('backBtn');

/* ---------- Helper: base64‑url encode / decode ---------- */
function b64UrlEncode(buf){
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
           .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function b64UrlDecode(str){
  str = str.replace(/-/g,'+').replace(/_/g,'/');
  while(str.length%4) str+='=';
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for(let i=0;i<binary.length;i++) bytes[i]=binary.charCodeAt(i);
  return bytes;
}

/* ---------- Crypto (unchanged) ---------- */
async function deriveKey(passphrase,salt){
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey('raw',enc.encode(passphrase),
                        {name:'PBKDF2'},false,['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2',salt,iterations:200_000,hash:'SHA-256'},
    baseKey,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
async function encryptMessage(plain,pass){
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(pass,salt);
  const cipherBuf = await crypto.subtle.encrypt({name:'AES-GCM',iv},key,enc.encode(plain));
  const combined = new Uint8Array([...salt,...iv,...new Uint8Array(cipherBuf)]);
  return b64UrlEncode(combined);
}
async function decryptMessage(b64Cipher,pass){
  const data = b64UrlDecode(b64Cipher);
  const salt = data.slice(0,16);
  const iv   = data.slice(16,28);
  const ct   = data.slice(28);
  const key = await deriveKey(pass,salt);
  const plainBuf = await crypto.subtle.decrypt({name:'AES-GCM',iv},key,ct);
  return new TextDecoder().decode(plainBuf);
}

/* ---------- Conversation handling (per passphrase) ---------- */
let activePassphrase = null;          // holds the passphrase for this session
let LOG_KEY = 'secureChatLog_default';

/* Generate a deterministic storage key from the passphrase */
async function storageKeyFor(pw){
  const enc = new TextEncoder();
  const hash = await crypto.subtle.digest('SHA-256',enc.encode(pw));
  const hex = Array.from(new Uint8Array(hash))
                   .map(b=>b.toString(16).padStart(2,'0')).join('');
  return `secureChatLog_${hex}`;
}

/* Show chat UI after successful login */
function showChat(){
  document.getElementById('loginOverlay').style.display='none';
  document.querySelector('header').style.display='flex';
  document.querySelector('main').style.display='block';
  document.querySelector('footer').style.display='flex';
}

/* Return to lock screen (logout) */
function goBack(){
  activePassphrase = null;
  LOG_KEY = 'secureChatLog_default';
  document.getElementById('loginOverlay').style.display='flex';
  document.querySelector('header').style.display='none';
  document.querySelector('main').style.display='none';
  document.querySelector('footer').style.display='none';
  logEl.innerHTML='';   // clear visible log
}

/* ---------- Login button ----------
   User enters a passphrase → we compute a unique LOG_KEY,
   load that conversation’s history, and reveal the chat UI. */
loginBtn.addEventListener('click', async ()=>{
  const pw = loginPw.value;
  if(!pw) return alert('Please type a passphrase');
  activePassphrase = pw;
  hiddenPw.value = pw;                 // store it for encrypt/decrypt calls
  LOG_KEY = await storageKeyFor(pw);
  renderLog();                         // load any existing messages for this passphrase
  showChat();
});

/* ---------- Back button ----------
   Returns to the lock screen so a different passphrase can be used. */
backBtn.addEventListener('click', goBack);

/* ---------- Log helpers (per‑conversation) ---------- */
function loadLog(){
  const raw = localStorage.getItem(LOG_KEY);
  return raw ? JSON.parse(raw) : [];
}
function saveLog(arr){
  localStorage.setItem(LOG_KEY,JSON.stringify(arr));
}
function addLogEntry(type,content){
  const arr = loadLog();
  arr.push({ts:Date.now(),type,content});
  if(arr.length>200) arr.shift();
  saveLog(arr);
  renderLog();
}

/* Render ONLY decrypted messages (type === 'dec') */
function renderLog(){
  const arr = loadLog();
  logEl.innerHTML='';
  arr.forEach(e=>{
    if(e.type==='dec'){
      const div=document.createElement('div');
      div.className='log-entry log-B';   // decrypted -> B colour
      const time=new Date(e.ts).toLocaleTimeString();
      div.innerHTML=`<span>${time} B:</span> ${e.content}`;
      logEl.appendChild(div);
    } else if(e.type==='enc'){
      // We keep encrypted entries for history but do NOT display them.
      // (If you ever want to show them, uncomment the block below.)
      /*
      const div=document.createElement('div');
      div.className='log-entry log-A';
      const time=new Date(e.ts).toLocaleTimeString();
      div.innerHTML=`<span>${time} A:</span> ${e.content}`;
      logEl.appendChild(div);
      */
    }
  });
  logEl.scrollTop = logEl.scrollHeight;
}

/* ---------- Encrypt button ----------
   Uses the hidden passphrase (set at login) */
encryptBtn.addEventListener('click', async ()=>{
  const plain = msgInput.value.trim();
  if(!plain) return alert('Write a message first');
  if(!activePassphrase) return alert('You must be logged in');

  try{
    const cipher = await encryptMessage(plain, hiddenPw.value);
    addLogEntry('enc', cipher);   // stored but not shown
    // ---- Share the ciphertext automatically ----
    if(navigator.canShare && navigator.share){
      try{
        await navigator.share({title:'Encrypted Message',text:cipher});
      }catch(_){ /* user cancelled share */ }
    }else if(navigator.clipboard){
      await navigator.clipboard.writeText(cipher);
      alert('Cipher copied to clipboard');
    }
    msgInput.value='';
  }catch(err){
    console.error(err);
    alert('Encryption failed');
  }
});

/* ---------- Decrypt button ----------
   Also uses the hidden passphrase */
decryptBtn.addEventListener('click', async ()=>{
  const cipher = msgInput.value.trim();
  if(!cipher) return alert('Paste a ciphertext to decrypt');
  if(!activePassphrase) return alert('You must be logged in');

  try{
    const plain = await decryptMessage(cipher, hiddenPw.value);
    addLogEntry('dec', plain);   // visible in log with “B:”
    msgInput.value='';
  }catch(err){
    console.error(err);
    alert('Decryption failed – maybe wrong passphrase or corrupted data');
  }
});

/* ------ Service‑worker registration (unchanged) ------ */
if('serviceWorker' in navigator){
  navigator.serviceWorker.register('sw.js')
    .catch(err=>console.warn('SW registration failed',err));
}

/* ------ Initial UI state (hide chat until login) ------ */
document.querySelector('header').style.display='none';
document.querySelector('main').style.display='none';
document.querySelector('footer').style.display='none';
