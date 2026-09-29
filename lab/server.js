import { createServer } from 'node:http';

const port = Number(process.env.PORT || 10000);

const server = createServer((req, res) => {
  if (req.url === '/healthz') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', name: 'trovex-private-lab' }));
    return;
  }

  if (req.method !== 'GET' || !['/', '/about'].includes(req.url)) {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('Not found');
    return;
  }

  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(`<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>Trovex Authorized Lab</title></head>
  <body>
    <main>
      <h1>Trovex Authorized Lab</h1>
      <p>Isolated training target for passive security-header monitoring.</p>
      <a href="/about">Lab information</a>
    </main>
  </body>
</html>`);
});

server.listen(port, '0.0.0.0', () => {
  console.log(`Private lab listening on port ${port}`);
});