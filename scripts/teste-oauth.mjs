// Teste manual do fluxo OAuth + MCP, sem precisar do Grok.
// Requer DEBUG_OAUTH=true no servidor.
//   1) npm run teste:oauth            -> mostra o URL para abrir no browser
//   2) npm run teste:oauth -- troca <código>   -> troca o código por tokens e lista as ferramentas
import 'dotenv/config';
import crypto from 'node:crypto';
import fs from 'node:fs';

const port = process.env.PORT || 3000;
const base = process.env.PUBLIC_BASE_URL
  || (process.env.CODESPACE_NAME
    ? `https://${process.env.CODESPACE_NAME}-${port}.${process.env.GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN || 'app.github.dev'}`
    : `http://localhost:${port}`);
const redirectUri = `${base}/oauth/debug-callback`;
const stateFile = '.oauth-teste.json';
const [cmd, code] = process.argv.slice(2);

if (cmd !== 'troca') {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  fs.writeFileSync(stateFile, JSON.stringify({ verifier }));
  const url = new URL(`${base}/oauth/authorize`);
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.OAUTH_CLIENT_ID,
    redirect_uri: redirectUri,
    scope: 'mcp:read mcp:write',
    state: crypto.randomBytes(8).toString('hex'),
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }).toString();
  console.log('Abre este URL no browser e faz login:\n\n' + url.toString() + '\n');
  process.exit(0);
}

const { verifier } = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
const tokenRes = await fetch(`${base}/oauth/token`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
    client_id: process.env.OAUTH_CLIENT_ID,
    client_secret: process.env.OAUTH_CLIENT_SECRET,
  }),
});
const tokens = await tokenRes.json();
console.log('Resposta do /oauth/token:', tokenRes.status, { ...tokens, access_token: tokens.access_token?.slice(0, 8) + '…', refresh_token: tokens.refresh_token?.slice(0, 8) + '…' });
if (!tokens.access_token) process.exit(1);

const mcpRes = await fetch(`${base}/mcp`, {
  method: 'POST',
  headers: {
    Authorization: `Bearer ${tokens.access_token}`,
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream',
  },
  body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
});
console.log('\nResposta do /mcp (tools/list):', mcpRes.status);
console.log(await mcpRes.text());
