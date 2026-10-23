import express from 'express';
import crypto from 'node:crypto';
import { config } from './config.js';
import { db, authClient } from './supabase.js';

export const router = express.Router();
const form = express.urlencoded({ extended: false });
const json = express.json();

// ---------- utilitários ----------
const sha256Hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
const sha256B64url = (s) => crypto.createHash('sha256').update(s).digest('base64url');
const randomToken = () => crypto.randomBytes(32).toString('base64url');
const escapeHtml = (s = '') =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function safeEqual(a, b) {
  const A = Buffer.from(String(a ?? ''));
  const B = Buffer.from(String(b ?? ''));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
}

function oauthError(res, status, error, description) {
  res.set('Cache-Control', 'no-store');
  return res.status(status).json({ error, error_description: description });
}

function normalizeScope(requested) {
  const asked = String(requested || '').split(/[\s,]+/).filter(Boolean);
  const granted = asked.filter((s) => config.scopes.includes(s));
  return (granted.length ? granted : config.scopes).join(' ');
}

// ---------- 1. Descoberta (metadados) ----------
// RFC 9728: o recurso protegido diz quem é o servidor de autorização
router.get(['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp'], (req, res) => {
  res.json({
    resource: `${config.baseUrl}/mcp`,
    authorization_servers: [config.baseUrl],
    scopes_supported: config.scopes,
    bearer_methods_supported: ['header'],
  });
});

// RFC 8414: metadados do servidor de autorização (o Grok usa-os para pré-preencher o formulário)
router.get(['/.well-known/oauth-authorization-server', '/.well-known/oauth-authorization-server/mcp'], (req, res) => {
  res.json({
    issuer: config.baseUrl,
    authorization_endpoint: `${config.baseUrl}/oauth/authorize`,
    token_endpoint: `${config.baseUrl}/oauth/token`,
    revocation_endpoint: `${config.baseUrl}/oauth/revoke`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
    scopes_supported: config.scopes,
  });
});

// ---------- 2. Autorização (página de login) ----------
function validateAuthorizeParams(p) {
  if (p.response_type !== 'code') return 'response_type tem de ser "code".';
  if (p.client_id !== config.clientId) return 'client_id desconhecido.';
  if (!config.redirectUris.includes(p.redirect_uri)) return `redirect_uri não autorizado: ${p.redirect_uri}`;
  if (p.code_challenge && (p.code_challenge_method || 'plain') !== 'S256') return 'Só aceitamos PKCE com S256.';
  return null;
}

function loginPage(p, errorMsg = '') {
  const hidden = ['response_type', 'client_id', 'redirect_uri', 'state', 'scope', 'code_challenge', 'code_challenge_method']
    .map((k) => `<input type="hidden" name="${k}" value="${escapeHtml(p[k] ?? '')}">`)
    .join('\n');
  return `<!doctype html><html lang="pt"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Autorizar acesso</title>
<style>
 body{font-family:system-ui,sans-serif;background:#f4f4f5;display:grid;place-items:center;min-height:100vh;margin:0}
 form{background:#fff;padding:28px;border-radius:12px;width:min(360px,90vw);box-shadow:0 2px 12px #0001}
 h1{font-size:20px;margin:0 0 8px} p{color:#555;font-size:14px}
 label{display:block;font-size:13px;margin-top:14px} input[type=email],input[type=password]{width:100%;padding:10px;margin-top:4px;border:1px solid #ccc;border-radius:8px;box-sizing:border-box}
 button{margin-top:20px;width:100%;padding:11px;border:0;border-radius:8px;background:#111;color:#fff;font-size:15px;cursor:pointer}
 .err{color:#b00020;font-size:14px}
</style></head><body>
<form method="post" action="/oauth/authorize">
<h1>Ligar ao Grok</h1>
<p>O Grok pede acesso às tuas notas (${escapeHtml(normalizeScope(p.scope))}). Entra com a tua conta.</p>
${errorMsg ? `<p class="err">${escapeHtml(errorMsg)}</p>` : ''}
${hidden}
<label>Email<input type="email" name="email" required autocomplete="username"></label>
<label>Palavra-passe<input type="password" name="password" required autocomplete="current-password"></label>
<button type="submit">Autorizar</button>
</form></body></html>`;
}

router.get('/oauth/authorize', (req, res) => {
  const err = validateAuthorizeParams(req.query);
  if (err) return res.status(400).send(`<p>Pedido inválido: ${escapeHtml(err)}</p>`);
  res.set('Cache-Control', 'no-store').send(loginPage(req.query));
});

router.post('/oauth/authorize', form, async (req, res) => {
  const p = req.body;
  const err = validateAuthorizeParams(p);
  if (err) return res.status(400).send(`<p>Pedido inválido: ${escapeHtml(err)}</p>`);

  // Valida o utilizador no Supabase Auth
  const { data, error } = await authClient().auth.signInWithPassword({
    email: String(p.email || ''),
    password: String(p.password || ''),
  });
  if (error || !data?.user) return res.status(401).send(loginPage(p, 'Email ou palavra-passe incorretos.'));

  const code = randomToken();
  const { error: insertError } = await db.from('oauth_codes').insert({
    code_hash: sha256Hex(code),
    client_id: p.client_id,
    user_id: data.user.id,
    redirect_uri: p.redirect_uri,
    code_challenge: p.code_challenge || null,
    scope: normalizeScope(p.scope),
    expires_at: new Date(Date.now() + config.codeTtlSeconds * 1000).toISOString(),
  });
  if (insertError) {
    console.error('Erro a guardar o código:', insertError);
    return res.status(500).send(loginPage(p, 'Erro interno. Tenta de novo.'));
  }

  const target = new URL(p.redirect_uri);
  target.searchParams.set('code', code);
  if (p.state) target.searchParams.set('state', p.state);
  res.redirect(302, target.toString());
});

// Página auxiliar só para testes manuais (DEBUG_OAUTH=true)
router.get('/oauth/debug-callback', (req, res) => {
  if (!config.debugOAuth) return res.status(404).end();
  res.send(`<p>Código recebido. Corre no terminal:</p><pre>npm run teste:oauth -- troca ${escapeHtml(req.query.code)}</pre>`);
});

// ---------- 3. Token ----------
// Lê o client_id e o client_secret do cabeçalho Basic ou do corpo do pedido
function readClientCredentials(req) {
  const header = req.headers.authorization || '';
  if (header.startsWith('Basic ')) {
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
    const i = decoded.indexOf(':');
    return {
      id: decodeURIComponent(i >= 0 ? decoded.slice(0, i) : decoded),
      secret: decodeURIComponent(i >= 0 ? decoded.slice(i + 1) : ''),
    };
  }
  return { id: req.body?.client_id, secret: req.body?.client_secret };
}

// Cliente do Grok (credenciais definidas nas variáveis de ambiente)
function authenticateClient(req) {
  const { id, secret } = readClientCredentials(req);
  if (id !== config.clientId) return { ok: false };
  if (secret) return { ok: safeEqual(secret, config.clientSecret), confidential: true };
  return { ok: true, confidential: false }; // cliente público: PKCE obrigatório
}

async function issueTokens({ clientId, userId, scope }) {
  const accessToken = randomToken();
  const refreshToken = randomToken();
  const now = Date.now();
  const { error } = await db.from('oauth_tokens').insert({
    access_token_hash: sha256Hex(accessToken),
    refresh_token_hash: sha256Hex(refreshToken),
    client_id: clientId,
    user_id: userId,
    scope,
    access_expires_at: new Date(now + config.accessTtlSeconds * 1000).toISOString(),
    refresh_expires_at: new Date(now + config.refreshTtlSeconds * 1000).toISOString(),
  });
  if (error) throw error;
  return {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: config.accessTtlSeconds,
    refresh_token: refreshToken,
    scope,
  };
}

// Lojas: grant client_credentials -> token só de escrita, ligado a uma loja, sem refresh token
async function issueStoreToken(req, res) {
  const { id, secret } = readClientCredentials(req);
  if (!id || !secret) return oauthError(res, 401, 'invalid_client', 'Indica client_id e client_secret da loja.');
  const { data: client, error } = await db.from('lojas_clientes')
    .select('client_id, secret_hash, id_loja, ativo').eq('client_id', String(id)).maybeSingle();
  if (error) throw error;
  if (!client || !client.ativo || !safeEqual(sha256Hex(String(secret)), client.secret_hash)) {
    return oauthError(res, 401, 'invalid_client', 'Credenciais da loja inválidas ou desativadas.');
  }
  const accessToken = randomToken();
  const expiresAt = new Date(Date.now() + config.accessTtlSeconds * 1000).toISOString();
  const { error: insertError } = await db.from('oauth_tokens').insert({
    access_token_hash: sha256Hex(accessToken),
    refresh_token_hash: null,
    client_id: client.client_id,
    user_id: null,
    id_loja: client.id_loja,
    scope: 'loja:write',
    access_expires_at: expiresAt,
    refresh_expires_at: expiresAt,
  });
  if (insertError) throw insertError;
  return res.set('Cache-Control', 'no-store').json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: config.accessTtlSeconds,
    scope: 'loja:write',
  });
}

router.post('/oauth/token', form, json, async (req, res) => {
  try {
    if (req.body?.grant_type === 'client_credentials') return await issueStoreToken(req, res);

    const client = authenticateClient(req);
    if (!client.ok) return oauthError(res, 401, 'invalid_client', 'Credenciais do cliente inválidas.');

    const body = req.body || {};

    if (body.grant_type === 'authorization_code') {
      const { data: row } = await db.from('oauth_codes').select('*').eq('code_hash', sha256Hex(String(body.code || ''))).maybeSingle();
      if (!row || row.used || new Date(row.expires_at) < new Date() || row.client_id !== config.clientId) {
        return oauthError(res, 400, 'invalid_grant', 'Código inválido ou expirado.');
      }
      if (body.redirect_uri && body.redirect_uri !== row.redirect_uri) {
        return oauthError(res, 400, 'invalid_grant', 'redirect_uri não coincide.');
      }
      if (row.code_challenge) {
        if (!body.code_verifier || sha256B64url(String(body.code_verifier)) !== row.code_challenge) {
          return oauthError(res, 400, 'invalid_grant', 'PKCE inválido (code_verifier).');
        }
      } else if (!client.confidential) {
        return oauthError(res, 400, 'invalid_request', 'Clientes sem segredo têm de usar PKCE.');
      }
      // Marca como usado de forma atómica (evita reutilização)
      const { data: claimed } = await db.from('oauth_codes').update({ used: true })
        .eq('code_hash', row.code_hash).eq('used', false).select('code_hash');
      if (!claimed?.length) return oauthError(res, 400, 'invalid_grant', 'Código já utilizado.');

      const tokens = await issueTokens({ clientId: row.client_id, userId: row.user_id, scope: row.scope });
      return res.set('Cache-Control', 'no-store').json(tokens);
    }

    if (body.grant_type === 'refresh_token') {
      const { data: row } = await db.from('oauth_tokens').select('*')
        .eq('refresh_token_hash', sha256Hex(String(body.refresh_token || ''))).maybeSingle();
      if (!row || row.revoked || new Date(row.refresh_expires_at) < new Date() || row.client_id !== config.clientId) {
        return oauthError(res, 400, 'invalid_grant', 'Refresh token inválido ou expirado.');
      }
      // Rotação: o refresh token antigo deixa de valer
      const { data: claimed } = await db.from('oauth_tokens').update({ revoked: true })
        .eq('id', row.id).eq('revoked', false).select('id');
      if (!claimed?.length) return oauthError(res, 400, 'invalid_grant', 'Refresh token já utilizado.');

      const tokens = await issueTokens({ clientId: row.client_id, userId: row.user_id, scope: row.scope });
      return res.set('Cache-Control', 'no-store').json(tokens);
    }

    return oauthError(res, 400, 'unsupported_grant_type', 'Usa authorization_code, refresh_token ou client_credentials.');
  } catch (err) {
    console.error('Erro no /oauth/token:', err);
    return oauthError(res, 500, 'server_error', 'Erro interno.');
  }
});

// ---------- 4. Revogação (opcional) ----------
router.post('/oauth/revoke', form, json, async (req, res) => {
  const client = authenticateClient(req);
  if (!client.ok) return oauthError(res, 401, 'invalid_client', 'Credenciais do cliente inválidas.');
  const hash = sha256Hex(String(req.body?.token || ''));
  await db.from('oauth_tokens').update({ revoked: true }).or(`access_token_hash.eq.${hash},refresh_token_hash.eq.${hash}`);
  res.status(200).end();
});

// ---------- 5. Middleware que protege o /mcp e a API das lojas ----------
// requireAuth('mcp:read')   -> tokens do Grok (utilizadores)
// requireAuth('loja:write') -> tokens das lojas (client_credentials)
export function requireAuth(requiredScope) {
  return async (req, res, next) => {
    const challenge = `Bearer resource_metadata="${config.baseUrl}/.well-known/oauth-protected-resource"`;
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
    if (!token) {
      res.set('WWW-Authenticate', challenge);
      return res.status(401).json({ error: 'invalid_token', error_description: 'Falta o token de acesso.' });
    }
    try {
      const { data } = await db.from('oauth_tokens')
        .select('user_id, id_loja, client_id, scope, access_expires_at, revoked')
        .eq('access_token_hash', sha256Hex(token)).maybeSingle();
      if (!data || data.revoked || new Date(data.access_expires_at) < new Date()) {
        res.set('WWW-Authenticate', `${challenge}, error="invalid_token"`);
        return res.status(401).json({ error: 'invalid_token', error_description: 'Token inválido ou expirado.' });
      }
      const scopes = (data.scope || '').split(' ').filter(Boolean);
      if (!scopes.includes(requiredScope)) {
        res.set('WWW-Authenticate', `${challenge}, error="insufficient_scope", scope="${requiredScope}"`);
        return res.status(403).json({ error: 'insufficient_scope', error_description: `Este token não tem o escopo ${requiredScope}.` });
      }
      // O SDK MCP passa req.auth para as ferramentas como extra.authInfo
      req.auth = {
        token,
        clientId: data.client_id,
        scopes,
        expiresAt: Math.floor(new Date(data.access_expires_at).getTime() / 1000),
        extra: { userId: data.user_id, idLoja: data.id_loja },
      };
      next();
    } catch (err) {
      console.error('Erro a validar token:', err);
      res.status(500).json({ error: 'server_error' });
    }
  };
}
