// Loopback-only HTTP proxy. External TCP sockets are opened by the host relay;
// this process never connects outside the network=none container.
const net = require('node:net');
const MAX_FRAME = 65536;
const CHUNK = 32768;
const sockets = new Map();
let nextId = 0;
let input = Buffer.alloc(0);
let stopping = false;

function frame(message, source) {
  if (stopping) return;
  const line = JSON.stringify(message) + '\n';
  if (Buffer.byteLength(line) > MAX_FRAME) return shutdown();
  if (!process.stdout.write(line) && source) {
    source.pause();
    process.stdout.once('drain', () => { if (!source.destroyed) source.resume(); });
  }
}

function sendData(id, data, source) {
  for (let offset = 0; offset < data.length; offset += CHUNK) {
    frame({ op: 'data', id, data: data.subarray(offset, offset + CHUNK).toString('base64') }, source);
  }
}

function fail(socket) {
  if (!socket.destroyed) socket.end('HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
}

function parseRequest(buffer) {
  const separator = buffer.indexOf('\r\n\r\n');
  if (separator < 0) return null;
  const header = buffer.subarray(0, separator).toString('latin1');
  if (header.length > 32768 || /[^\x09\x20-\x7e\r\n]/.test(header)) throw new Error();
  const lines = header.split('\r\n');
  const match = /^(CONNECT|GET|HEAD) (\S+) HTTP\/1\.[01]$/.exec(lines.shift());
  if (!match) throw new Error();
  const [, method, target] = match;
  if (target.length > 8192 || target.includes('\\')) throw new Error();
  const url = new URL(method === 'CONNECT' ? `http://${target}` : target);
  if (url.username || url.password || url.hash || !url.hostname || url.hostname.length > 253) throw new Error();
  const port = Number(url.port || (method === 'CONNECT' ? 0 : 80));
  if (method === 'CONNECT') {
    if (url.pathname !== '/' || url.search || port !== 443 || target.includes('/')) throw new Error();
    return { host: url.hostname, port, connect: true, initial: buffer.subarray(separator + 4) };
  }
  if (url.protocol !== 'http:' || port !== 80 || buffer.length !== separator + 4) throw new Error();
  const forwarded = [];
  for (const line of lines) {
    const colon = line.indexOf(':');
    if (colon < 1 || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(line.slice(0, colon))) throw new Error();
    const name = line.slice(0, colon).toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (/[\r\n]/.test(value)) throw new Error();
    if (name === 'content-length' && value !== '0') throw new Error();
    if (['transfer-encoding', 'upgrade'].includes(name)) throw new Error();
    if (['host', 'proxy-authorization', 'proxy-connection', 'connection', 'keep-alive', 'content-length', 'te', 'trailer'].includes(name)) continue;
    forwarded.push(`${line.slice(0, colon)}: ${value}`);
  }
  const request = `${method} ${url.pathname}${url.search} HTTP/1.1\r\nHost: ${url.hostname}\r\nConnection: close\r\n${forwarded.join('\r\n')}${forwarded.length ? '\r\n' : ''}\r\n`;
  return { host: url.hostname, port, connect: false, initial: Buffer.from(request, 'latin1') };
}

const server = net.createServer(socket => {
  if (stopping || sockets.size >= 16 || nextId >= 100) return fail(socket);
  socket.setTimeout(30000, () => socket.destroy());
  const id = String(++nextId);
  const state = { socket, header: Buffer.alloc(0), parsed: null, connected: false };
  sockets.set(id, state);
  socket.on('error', () => socket.destroy());
  socket.on('close', () => { sockets.delete(id); frame({ op: 'end', id }); });
  socket.on('data', data => {
    if (state.connected) {
      if (!state.parsed.connect) return socket.destroy();
      return sendData(id, data, socket);
    }
    if (state.parsed) return socket.destroy();
    state.header = Buffer.concat([state.header, data]);
    if (state.header.length > 32768) return fail(socket);
    try {
      state.parsed = parseRequest(state.header);
      if (!state.parsed) return;
      state.header = null;
      socket.pause();
      frame({ op: 'connect', id, host: state.parsed.host, port: state.parsed.port });
    } catch { fail(socket); }
  });
});

function receive(message) {
  if (message?.op === 'shutdown') return shutdown();
  if (!message || typeof message.id !== 'string' || !/^[1-9][0-9]{0,5}$/.test(message.id)) throw new Error();
  const state = sockets.get(message.id);
  if (!state) return;
  const { socket } = state;
  if (message.op === 'connected') {
    if (!state.parsed || state.connected) throw new Error();
    state.connected = true;
    if (state.parsed.connect) socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (state.parsed.initial.length) sendData(message.id, state.parsed.initial, socket);
    state.parsed.initial = Buffer.alloc(0);
    socket.resume();
  } else if (message.op === 'data') {
    if (!state.connected || typeof message.data !== 'string' || message.data.length > 43692
        || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(message.data)) throw new Error();
    const data = Buffer.from(message.data, 'base64');
    if (data.length > CHUNK) throw new Error();
    if (!socket.write(data)) {
      process.stdin.pause();
      socket.once('drain', () => process.stdin.resume());
    }
  } else if (message.op === 'end') {
    socket.end();
  } else if (message.op === 'error') {
    if (state.connected) socket.destroy(); else fail(socket);
  } else {
    throw new Error();
  }
}

process.stdin.on('data', data => {
  input = Buffer.concat([input, data]);
  while (true) {
    const newline = input.indexOf(10);
    if (newline < 0) break;
    if (newline + 1 > MAX_FRAME) return shutdown();
    const line = input.subarray(0, newline);
    input = input.subarray(newline + 1);
    try { receive(JSON.parse(line.toString('utf8'))); } catch { return shutdown(); }
  }
  if (input.length >= MAX_FRAME) shutdown();
});
function shutdown() {
  if (stopping) return;
  stopping = true;
  for (const { socket } of sockets.values()) socket.destroy();
  sockets.clear();
  server.close();
  process.stdin.destroy();
  process.stdout.end(() => process.exit(0));
  // A stopped host may no longer drain stdout. Never leave this docker exec
  // process or its loopback listener alive while waiting for that pipe.
  setTimeout(() => process.exit(0), 100);
}
process.stdin.on('end', shutdown);
process.stdin.on('error', shutdown);
process.stdout.on('error', shutdown);
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
server.on('error', shutdown);
server.listen(3128, '127.0.0.1', () => frame({ op: 'ready' }));
