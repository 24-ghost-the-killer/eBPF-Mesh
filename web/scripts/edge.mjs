// SPDX-License-Identifier: MIT OR Apache-2.0
// Same-origin front for development and the browser tests: /api/v1/* (HTTP
// and WebSocket) goes to the API, everything else to Next.js. Production
// uses a real reverse proxy with TLS (docs/running.md); the API then runs
// with trust_proxy = true because this sets X-Forwarded-For.
//
//   EDGE_LISTEN=127.0.0.1:3000 API_ORIGIN=http://127.0.0.1:8080 \
//   WEB_ORIGIN=http://127.0.0.1:3001 node scripts/edge.mjs
import http from "node:http";
import net from "node:net";

const [host, port] = (process.env.EDGE_LISTEN ?? "127.0.0.1:3000").split(":");
const api = new URL(process.env.API_ORIGIN ?? "http://127.0.0.1:8080");
const web = new URL(process.env.WEB_ORIGIN ?? "http://127.0.0.1:3001");

const target = (path) => (path.startsWith("/api/") ? api : web);

function forwardedHeaders(req) {
  const h = { ...req.headers };
  // Overwrite (never append to) X-Forwarded-For: the client cannot spoof it.
  h["x-forwarded-for"] = req.socket.remoteAddress ?? "";
  h["x-forwarded-proto"] = "http";
  h["x-forwarded-host"] = req.headers.host ?? "";
  return h;
}

const server = http.createServer((req, res) => {
  const t = target(req.url ?? "/");
  const up = http.request(
    { host: t.hostname, port: t.port, method: req.method, path: req.url, headers: forwardedHeaders(req) },
    (r) => {
      res.writeHead(r.statusCode ?? 502, r.headers);
      r.pipe(res);
    },
  );
  up.on("error", () => {
    if (!res.headersSent) res.writeHead(502, { "content-type": "text/plain" });
    res.end("upstream unavailable");
  });
  req.pipe(up);
});

// WebSocket upgrades: raw TCP splice after replaying the request head.
server.on("upgrade", (req, socket, head) => {
  const t = target(req.url ?? "/");
  const up = net.connect(Number(t.port), t.hostname, () => {
    const h = forwardedHeaders(req);
    let head0 = `${req.method} ${req.url} HTTP/1.1\r\n`;
    for (const [k, v] of Object.entries(h)) {
      for (const one of Array.isArray(v) ? v : [v]) if (one !== undefined) head0 += `${k}: ${one}\r\n`;
    }
    up.write(head0 + "\r\n");
    if (head.length) up.write(head);
    socket.pipe(up).pipe(socket);
  });
  up.on("error", () => socket.destroy());
  socket.on("error", () => up.destroy());
});

server.listen(Number(port), host, () => {
  console.log(`edge listening on http://${host}:${port} (api ${api.origin}, web ${web.origin})`);
});
