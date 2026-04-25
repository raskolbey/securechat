const express = require('express');
const { WebSocketServer } = require('ws');
const http = require('http');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

app.use(express.static(path.join(__dirname, 'public')));

const ADJECTIVES = [
  'Swift', 'Brave', 'Silent', 'Dark', 'Bright', 'Calm', 'Wild', 'Sleek',
  'Mystic', 'Cosmic', 'Neon', 'Shadow', 'Electric', 'Frozen', 'Burning',
  'Crystal', 'Phantom', 'Turbo', 'Stealth', 'Iron'
];

const NOUNS = [
  'Fox', 'Bear', 'Wolf', 'Eagle', 'Lion', 'Tiger', 'Hawk', 'Lynx',
  'Puma', 'Crow', 'Viper', 'Raven', 'Shark', 'Cobra', 'Panther',
  'Phoenix', 'Dragon', 'Ghost', 'Storm', 'Cipher'
];

// nick -> { ws, publicKey }
const clients = new Map();

function generateNick() {
  let nick;
  let attempts = 0;
  do {
    const adj = ADJECTIVES[Math.floor(Math.random() * ADJECTIVES.length)];
    const noun = NOUNS[Math.floor(Math.random() * NOUNS.length)];
    const num = Math.floor(Math.random() * 100);
    nick = `${adj}${noun}${num}`;
    if (++attempts > 2000) { nick += Date.now(); break; }
  } while (clients.has(nick));
  return nick;
}

function broadcastUsers() {
  const users = [];
  clients.forEach((data, nick) => {
    if (data.publicKey) users.push(nick);
  });
  const msg = JSON.stringify({ type: 'users', users });
  clients.forEach(({ ws }) => {
    if (ws.readyState === 1) ws.send(msg);
  });
}

wss.on('connection', (ws) => {
  const nick = generateNick();
  clients.set(nick, { ws, publicKey: null });
  console.log(`[+] ${nick} connected  (total: ${clients.size})`);

  ws.send(JSON.stringify({ type: 'welcome', nick }));

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    switch (msg.type) {
      case 'register': {
        if (typeof msg.publicKey !== 'string' || msg.publicKey.length > 8192) return;
        clients.get(nick).publicKey = msg.publicKey;
        broadcastUsers();
        break;
      }

      case 'getKey': {
        if (typeof msg.nick !== 'string') return;
        const target = clients.get(msg.nick);
        if (target?.publicKey) {
          ws.send(JSON.stringify({ type: 'publicKey', nick: msg.nick, key: target.publicKey }));
        } else {
          ws.send(JSON.stringify({ type: 'error', code: 'USER_NOT_FOUND', nick: msg.nick }));
        }
        break;
      }

      case 'message': {
        if (
          typeof msg.to !== 'string' ||
          typeof msg.encryptedMsg !== 'string' ||
          typeof msg.encryptedKey !== 'string' ||
          typeof msg.iv !== 'string'
        ) return;

        const target = clients.get(msg.to);
        if (target?.ws?.readyState === 1) {
          target.ws.send(JSON.stringify({
            type: 'message',
            from: nick,
            encryptedMsg: msg.encryptedMsg,
            encryptedKey: msg.encryptedKey,
            iv: msg.iv,
            timestamp: Date.now()
          }));
          ws.send(JSON.stringify({ type: 'delivered', to: msg.to }));
        } else {
          ws.send(JSON.stringify({ type: 'error', code: 'USER_OFFLINE', nick: msg.to }));
        }
        break;
      }
    }
  });

  ws.on('close', () => {
    clients.delete(nick);
    console.log(`[-] ${nick} disconnected (total: ${clients.size})`);
    broadcastUsers();
  });

  ws.on('error', (err) => console.error(`[!] ${nick}: ${err.message}`));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`SecureChat → http://localhost:${PORT}`));
