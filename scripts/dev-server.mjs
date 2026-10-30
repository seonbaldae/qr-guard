// Local development server: serves the static frontend and forwards /api/* to the Python backend,
// so the browser sees one origin (no CORS) as it would behind a production reverse proxy.
//   terminal 1: python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1
//   terminal 2: node scripts/dev-server.mjs        (open http://127.0.0.1:8080/)
// Uses only Node.js built-ins. Not part of the Vercel static output.
import { createServer, request } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const staticRoot = process.argv.includes('--public') ? join(root, 'dist') : root;
const port = Number(process.env.PORT || 8080);
const backend = new URL(process.env.QR_GUARD_API || 'http://127.0.0.1:8000');
const served = ['index.html', 'src', 'assets', join('tests', 'frontend')];
const types = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png',
};

function staticPath(pathname) {
  const relative = normalize(decodeURIComponent(pathname === '/' ? '/index.html' : pathname)).replace(/^[/\\]+/, '');
  const target = resolve(staticRoot, relative);
  const allowed = served.some((entry) => target === join(staticRoot, entry) || target.startsWith(join(staticRoot, entry) + sep));
  return allowed ? target : null;
}

function proxy(req, res) {
  const upstream = request({
    hostname: backend.hostname, port: backend.port, path: req.url, method: req.method,
    headers: { ...req.headers, host: req.headers.host || backend.host },
  }, (response) => {
    res.writeHead(response.statusCode, response.headers);
    response.pipe(res);
  });
  upstream.on('error', () => {
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end('{"detail":"Backend unavailable"}');
  });
  req.pipe(upstream);
}

createServer(async (req, res) => {
  const { pathname } = new URL(req.url, 'http://localhost');
  if (pathname.startsWith('/api/')) return proxy(req, res);
  try {
    const target = staticPath(pathname);
    if (!target) throw Object.assign(new Error('not found'), { code: 'ENOENT' });
    const body = await readFile(target);
    res.writeHead(200, { 'Content-Type': types[extname(target)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
    res.end(body);
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
  }
}).listen(port, '127.0.0.1', () => console.log(`Frontend http://127.0.0.1:${port}/  ->  API ${backend.origin}`));
