import 'dotenv/config'; 
 
const port = Number(process.env.PORT || 3000); 
 
function required(name) { 
  const value = process.env[name]; 
  if (!value) throw new Error(`Falta a variável de ambiente ${name} (ver .env.example)`); 
  return value; 
} 
 
// URL público do servidor. No Codespaces é calculado a partir das variáveis 
// CODESPACE_NAME e GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN. 
function publicBaseUrl() { 
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL.replace(/\/+$/, ''); 
  if (process.env.CODESPACE_NAME) { 
    const domain = process.env.GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN || 'app.github.dev'; 
    return `https://${process.env.CODESPACE_NAME}-${port}.${domain}`; 
  } 
  return `http://localhost:${port}`; 
} 
 
export const config = { 
  port, 
  baseUrl: publicBaseUrl(), 
  supabaseUrl: required('SUPABASE_URL'), 
  supabaseSecretKey: required('SUPABASE_SECRET_KEY'), 
  supabasePublishableKey: required('SUPABASE_PUBLISHABLE_KEY'), 
  clientId: required('OAUTH_CLIENT_ID'), 
  clientSecret: required('OAUTH_CLIENT_SECRET'), 
 
 
  redirectUris: (process.env.OAUTH_REDIRECT_URIS || 'https://grok.com/connectors-oauth-exchange-code/') 
    .split(',') 
    .map((s) => s.trim()) 
    .filter(Boolean), 
  scopes: ['mcp:read', 'mcp:write'], 
  codeTtlSeconds: 5 * 60, 
  accessTtlSeconds: 60 * 60,            // 1 hora 
  refreshTtlSeconds: 60 * 60 * 24 * 30, // 30 dias 
  debugOAuth: process.env.DEBUG_OAUTH === 'true', 
}; 
 
if (config.debugOAuth) { 
  config.redirectUris.push(`${config.baseUrl}/oauth/debug-callback`); 
} 