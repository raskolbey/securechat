'use strict';

const subtle = window.crypto.subtle;

let myNick       = null;
let myKeyPair    = null;
let ws           = null;
let currentChat  = null;

const conversations   = {};  // nick -> [{from, text, ts, sent}]
const keyCache        = {};  // nick -> CryptoKey (recipient public key)
const pendingQueue    = {};  // nick -> text (waiting for key fetch)
const unread          = new Set();

// ── Boot ──────────────────────────────────────────────────────────────────────

async function init() {
  myKeyPair = await subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt']
  );
  connectWS();
  setupUI();
}

// ── WebSocket ─────────────────────────────────────────────────────────────────

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${proto}//${location.host}`);
  ws.addEventListener('open',    ()  => setStatus('connected'));
  ws.addEventListener('close',   ()  => { setStatus('disconnected'); setTimeout(connectWS, 3000); });
  ws.addEventListener('error',   ()  => setStatus('disconnected'));
  ws.addEventListener('message', (e) => handleServerMsg(JSON.parse(e.data)).catch(console.error));
}

function send(obj) {
  if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

// ── Server messages ───────────────────────────────────────────────────────────

async function handleServerMsg(msg) {
  switch (msg.type) {

    case 'welcome': {
      myNick = msg.nick;
      document.getElementById('my-nick').textContent = myNick;
      const spki = await subtle.exportKey('spki', myKeyPair.publicKey);
      send({ type: 'register', publicKey: bufToB64(spki) });
      break;
    }

    case 'users':
      renderUsers(msg.users.filter(n => n !== myNick));
      break;

    case 'publicKey': {
      keyCache[msg.nick] = await subtle.importKey(
        'spki', b64ToBuf(msg.key),
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false, ['encrypt']
      );
      if (pendingQueue[msg.nick]) {
        const text = pendingQueue[msg.nick];
        delete pendingQueue[msg.nick];
        await encryptAndSend(msg.nick, text);
      }
      break;
    }

    case 'message': {
      const text = await decrypt(msg.encryptedKey, msg.encryptedMsg, msg.iv);
      pushMsg(msg.from, { from: msg.from, text, ts: msg.timestamp, sent: false });
      if (currentChat !== msg.from) {
        unread.add(msg.from);
        refreshUnread();
        showToast(`${msg.from}: ${text.slice(0, 50)}`);
      }
      break;
    }

    case 'error':
      if (msg.code === 'USER_NOT_FOUND') showToast(`"${msg.nick}" bulunamadı`);
      if (msg.code === 'USER_OFFLINE')   showToast(`"${msg.nick}" şu an çevrimdışı`);
      break;
  }
}

// ── Crypto ────────────────────────────────────────────────────────────────────

async function encryptAndSend(to, text) {
  const recipientKey = keyCache[to];
  if (!recipientKey) return;

  // Random AES-256-GCM key + IV
  const aesKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const iv     = window.crypto.getRandomValues(new Uint8Array(12));

  // Encrypt plaintext
  const encMsg = await subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    new TextEncoder().encode(text)
  );

  // Wrap AES key with recipient's RSA public key
  const rawAes = await subtle.exportKey('raw', aesKey);
  const encKey = await subtle.encrypt({ name: 'RSA-OAEP' }, recipientKey, rawAes);

  send({
    type: 'message', to,
    encryptedMsg: bufToB64(encMsg),
    encryptedKey: bufToB64(encKey),
    iv:           bufToB64(iv)
  });
}

async function decrypt(encKeyB64, encMsgB64, ivB64) {
  // Unwrap AES key with our RSA private key
  const rawAes = await subtle.decrypt(
    { name: 'RSA-OAEP' }, myKeyPair.privateKey, b64ToBuf(encKeyB64)
  );
  const aesKey = await subtle.importKey('raw', rawAes, { name: 'AES-GCM' }, false, ['decrypt']);

  const plain = await subtle.decrypt(
    { name: 'AES-GCM', iv: b64ToBuf(ivB64) },
    aesKey,
    b64ToBuf(encMsgB64)
  );
  return new TextDecoder().decode(plain);
}

// ── Send flow ─────────────────────────────────────────────────────────────────

async function sendMessage() {
  const input = document.getElementById('msg-input');
  const text  = input.value.trim();
  if (!text || !currentChat || ws?.readyState !== WebSocket.OPEN) return;
  input.value = '';

  pushMsg(currentChat, { from: myNick, text, ts: Date.now(), sent: true });

  if (!keyCache[currentChat]) {
    pendingQueue[currentChat] = text;
    send({ type: 'getKey', nick: currentChat });
  } else {
    await encryptAndSend(currentChat, text);
  }
}

// ── UI helpers ────────────────────────────────────────────────────────────────

function openChat(nick) {
  currentChat = nick;
  unread.delete(nick);
  refreshUnread();

  document.getElementById('empty-state').style.display  = 'none';
  document.getElementById('chat-window').style.display  = 'flex';
  document.getElementById('chat-title').textContent     = nick;
  document.querySelector('.app').classList.add('chat-open');

  const container = document.getElementById('messages');
  container.innerHTML = '';
  (conversations[nick] || []).forEach(m => appendBubble(m));
  scrollBottom();

  if (!keyCache[nick]) send({ type: 'getKey', nick });

  document.getElementById('msg-input').focus();

  document.querySelectorAll('.user-item').forEach(el =>
    el.classList.toggle('active', el.dataset.nick === nick)
  );
}

function pushMsg(nick, msg) {
  if (!conversations[nick]) conversations[nick] = [];
  conversations[nick].push(msg);
  if (currentChat === nick) { appendBubble(msg); scrollBottom(); }
}

function appendBubble(msg) {
  const wrap = document.createElement('div');
  wrap.className = `message ${msg.sent ? 'sent' : 'received'}`;
  wrap.innerHTML = `
    <div class="bubble">${esc(msg.text)}</div>
    <div class="msg-time">${fmtTime(msg.ts)}</div>
  `;
  document.getElementById('messages').appendChild(wrap);
}

function renderUsers(users) {
  const list = document.getElementById('user-list');
  if (!users.length) {
    list.innerHTML = '<div class="empty-list">Henüz başka kullanıcı yok</div>';
    return;
  }
  list.innerHTML = '';
  users.forEach(nick => {
    const el = document.createElement('div');
    el.className = `user-item${currentChat === nick ? ' active' : ''}`;
    el.dataset.nick = nick;
    el.innerHTML = `
      <div class="avatar">${nick[0].toUpperCase()}</div>
      <div class="user-nick">${esc(nick)}</div>
      ${unread.has(nick) ? '<div class="unread-dot"></div>' : ''}
    `;
    el.addEventListener('click', () => openChat(nick));
    list.appendChild(el);
  });
}

function refreshUnread() {
  document.querySelectorAll('.user-item').forEach(el => {
    const nick = el.dataset.nick;
    const dot  = el.querySelector('.unread-dot');
    if (unread.has(nick) && !dot) el.insertAdjacentHTML('beforeend', '<div class="unread-dot"></div>');
    else if (!unread.has(nick) && dot) dot.remove();
  });
}

function setStatus(state) {
  const el    = document.getElementById('conn-status');
  const label = document.getElementById('conn-label');
  el.className = `conn-status ${state}`;
  label.textContent = { connected: 'Bağlı', disconnected: 'Bağlantı kesildi', connecting: 'Bağlanıyor…' }[state] ?? state;
}

function showToast(text) {
  const t = document.createElement('div');
  t.className   = 'toast';
  t.textContent = text;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3000);
}

function scrollBottom() {
  const el = document.getElementById('messages');
  el.scrollTop = el.scrollHeight;
}

// ── Utility ───────────────────────────────────────────────────────────────────

function bufToB64(buf) {
  const bytes  = new Uint8Array(buf);
  let   binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function b64ToBuf(b64) {
  const binary = atob(b64);
  const bytes  = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function esc(str) {
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function fmtTime(ts) {
  return new Date(ts).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' });
}

// ── Event listeners ───────────────────────────────────────────────────────────

function setupUI() {
  document.getElementById('send-btn').addEventListener('click', sendMessage);

  document.getElementById('msg-input').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });

  document.getElementById('copy-nick').addEventListener('click', () => {
    if (!myNick) return;
    navigator.clipboard.writeText(myNick).then(() => showToast('Nick kopyalandı!'));
  });

  const startChat = () => {
    const input = document.getElementById('search-nick');
    const nick  = input.value.trim();
    if (!nick) return;
    if (nick === myNick) { showToast('Kendinize mesaj atamazsınız'); return; }
    input.value = '';
    openChat(nick);
  };

  document.getElementById('start-chat-btn').addEventListener('click', startChat);
  document.getElementById('search-nick').addEventListener('keydown', e => {
    if (e.key === 'Enter') startChat();
  });

  document.getElementById('back-btn').addEventListener('click', () => {
    document.querySelector('.app').classList.remove('chat-open');
    currentChat = null;
  });
}

// ── Start ─────────────────────────────────────────────────────────────────────

init().catch(console.error);

function send(obj) {
  if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

// ── Server messages ───────────────────────────────────────────────────────────

async function handleServerMsg(msg) {
  switch (msg.type) {

    case 'welcome': {
      myNick = msg.nick;
      document.getElementById('my-nick').textContent = myNick;
      const spki = await subtle.exportKey('spki', myKeyPair.publicKey);
      send({ type: 'register', publicKey: bufToB64(spki) });
      break;
    }

    case 'users':
      renderUsers(msg.users.filter(n => n !== myNick));
      break;

    case 'publicKey': {
      keyCache[msg.nick] = await subtle.importKey(
        'spki', b64ToBuf(msg.key),
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false, ['encrypt']
      );
      if (pendingQueue[msg.nick]) {
        const text = pendingQueue[msg.nick];
        delete pendingQueue[msg.nick];
        await encryptAndSend(msg.nick, text);
      }
      break;
    }

    case 'message': {
      const text = await decrypt(msg.encryptedKey, msg.encryptedMsg, msg.iv);
      pushMsg(msg.from, { from: msg.from, text, ts: msg.timestamp, sent: false });
      if (currentChat !== msg.from) {
        unread.add(msg.from);
        refreshUnread();
        showToast(`${msg.from}: ${text.slice(0, 50)}`);
      }
      break;
    }

    case 'error':
      if (msg.code === 'USER_NOT_FOUND') showToast(`"${msg.nick}" bulunamadı`);
      if (msg.code === 'USER_OFFLINE')   showToast(`"${msg.nick}" şu an çevrimdışı`);
      break;
  }
}

// ── Crypto ────────────────────────────────────────────────────────────────────

async function encryptAndSend(to, text) {
  const recipientKey = keyCache[to];
  if (!recipientKey) return;

  // Random AES-256-GCM key + IV
  const aesKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const iv     = window.crypto.getRandomValues(new Uint8Array(12));

  // Encrypt plaintext
  const encMsg = await subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    new TextEncoder().encode(text)
  );

  // Wrap AES key with recipient's RSA public key
  const rawAes = await subtle.exportKey('raw', aesKey);
  const encKey = await subtle.encrypt({ name: 'RSA-OAEP' }, recipientKey, rawAes);

  send({
    type: 'message', to,
    encryptedMsg: bufToB64(encMsg),
    encryptedKey: bufToB64(encKey),
    iv:           bufToB64(iv)
  });
}

async function decrypt(encKeyB64, encMsgB64, ivB64) {
  // Unwrap AES key with our RSA private key
  const rawAes = await subtle.decrypt(
    { name: 'RSA-OAEP' }, myKeyPair.privateKey, b64ToBuf(encKeyB64)
  );
  const aesKey = await subtle.importKey('raw', rawAes, { name: 'AES-GCM' }, false, ['decrypt']);

  const plain = await subtle.decrypt(
    { name: 'AES-GCM', iv: b64ToBuf(ivB64) },
    aesKey,
    b64ToBuf(encMsgB64)
  );
  return new TextDecoder().decode(plain);
}

// ── Send flow ─────────────────────────────────────────────────────────────────

async function sendMessage() {
  const input = document.getElementById('msg-input');
  const text  = input.value.trim();
  if (!text || !currentChat || ws?.readyState !== WebSocket.OPEN) return;
  input.value = '';

  pushMsg(currentChat, { from: myNick, text, ts: Date.now(), sent: true });

  if (!keyCache[currentChat]) {
    pendingQueue[currentChat] = text;
    send({ type: 'getKey', nick: currentChat });
  } else {
    await encryptAndSend(currentChat, text);
  }
}

// ── UI helpers ────────────────────────────────────────────────────────────────

function openChat(nick) {
  currentChat = nick;
  unread.delete(nick);
  refreshUnread();

  document.getElementById('empty-state').style.display  = 'none';
  document.getElementById('chat-window').style.display  = 'flex';
  document.getElementById('chat-title').textContent     = nick;

  const container = document.getElementById('messages');
  container.innerHTML = '';
  (conversations[nick] || []).forEach(m => appendBubble(m));
  scrollBottom();

  if (!keyCache[nick]) send({ type: 'getKey', nick });

  document.getElementById('msg-input').focus();

  document.querySelectorAll('.user-item').forEach(el =>
    el.classList.toggle('active', el.dataset.nick === nick)
  );
}

function pushMsg(nick, msg) {
  if (!conversations[nick]) conversations[nick] = [];
  conversations[nick].push(msg);
  if (currentChat === nick) { appendBubble(msg); scrollBottom(); }
}

function appendBubble(msg) {
  const wrap = document.createElement('div');
  wrap.className = `message ${msg.sent ? 'sent' : 'received'}`;
  wrap.innerHTML = `
    <div class="bubble">${esc(msg.text)}</div>
    <div class="msg-time">${fmtTime(msg.ts)}</div>
  `;
  document.getElementById('messages').appendChild(wrap);
}

function renderUsers(users) {
  const list = document.getElementById('user-list');
  if (!users.length) {
    list.innerHTML = '<div class="empty-list">Henüz başka kullanıcı yok</div>';
    return;
  }
  list.innerHTML = '';
  users.forEach(nick => {
    const el = document.createElement('div');
    el.className = `user-item${currentChat === nick ? ' active' : ''}`;
    el.dataset.nick = nick;
    el.innerHTML = `
      <div class="avatar">${nick[0].toUpperCase()}</div>
      <div class="user-nick">${esc(nick)}</div>
      ${unread.has(nick) ? '<div class="unread-dot"></div>' : ''}
    `;
    el.addEventListener('click', () => openChat(nick));
    list.appendChild(el);
  });
}

function refreshUnread() {
  document.querySelectorAll('.user-item').forEach(el => {
    const nick = el.dataset.nick;
    const dot  = el.querySelector('.unread-dot');
    if (unread.has(nick) && !dot) el.insertAdjacentHTML('beforeend', '<div class="unread-dot"></div>');
    else if (!unread.has(nick) && dot) dot.remove();
  });
}

function setStatus(state) {
  const el    = document.getElementById('conn-status');
  const label = document.getElementById('conn-label');
  el.className = `conn-status ${state}`;
  label.textContent = { connected: 'Bağlı', disconnected: 'Bağlantı kesildi', connecting: 'Bağlanıyor…' }[state] ?? state;
}

function showToast(text) {
  const t = document.createElement('div');
  t.className   = 'toast';
  t.textContent = text;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3000);
}

function scrollBottom() {
  const el = document.getElementById('messages');
  el.scrollTop = el.scrollHeight;
}

// ── Utility ───────────────────────────────────────────────────────────────────

function bufToB64(buf) {
  const bytes  = new Uint8Array(buf);
  let   binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function b64ToBuf(b64) {
  const binary = atob(b64);
  const bytes  = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function esc(str) {
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function fmtTime(ts) {
  return new Date(ts).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' });
}

// ── Event listeners ───────────────────────────────────────────────────────────

function setupUI() {
  document.getElementById('send-btn').addEventListener('click', sendMessage);

  document.getElementById('msg-input').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });

  document.getElementById('copy-nick').addEventListener('click', () => {
    if (!myNick) return;
    navigator.clipboard.writeText(myNick).then(() => showToast('Nick kopyalandı!'));
  });

  const startChat = () => {
    const input = document.getElementById('search-nick');
    const nick  = input.value.trim();
    if (!nick) return;
    if (nick === myNick) { showToast('Kendinize mesaj atamazsınız'); return; }
    input.value = '';
    openChat(nick);
  };

  document.getElementById('start-chat-btn').addEventListener('click', startChat);
  document.getElementById('search-nick').addEventListener('keydown', e => {
    if (e.key === 'Enter') startChat();
  });
}

// ── Start ─────────────────────────────────────────────────────────────────────

init().catch(console.error);
