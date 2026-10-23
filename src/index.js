import express from 'express'; 
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'; 
import { config } from './config.js'; 
import { router as oauthRouter, requireAuth } from './oauth.js'; 
import { buildServer } from './mcp.js';

const app = express(); 
app.set('trust proxy', true); // o Codespaces está atrás de um proxy HTTPS 

// Registo simples de pedidos (ajuda muito a depurar a ligação ao Grok) 
app.use((req, res, next) => { 
  res.on('finish', () => console.log(`${req.method} ${req.path} -> ${res.statusCode}`)); 
  next(); 
});

app.use(oauthRouter); 

app.get('/', (req, res) => { 
  res.type('text').send(`Servidor MCP ativo.\nEndpoint MCP: ${config.baseUrl}/mcp\n`); 
}); 

// Endpoint MCP (Streamable HTTP, modo stateless: um servidor novo por pedido) 
app.post('/mcp', requireAuth, express.json({ limit: '1mb' }), async (req, res) => { 
  const server = buildServer(); 
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined }); 
  res.on('close', () => { 
    transport.close(); 
    server.close(); 
  }); 
  try { 
    await server.connect(transport); 
    await transport.handleRequest(req, res, req.body); 
  } catch (err) { 
    console.error('Erro no /mcp:', err); 
    if (!res.headersSent) { 
      res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Erro interno' }, id: null }); 
    } 
  } 
}); 


// Em modo stateless não há stream GET nem sessões para apagar 
const notAllowed = (req, res) => res.status(405).set('Allow', 'POST').json({ jsonrpc: '2.0', error: { code: -32000, message: 'Método não permitido' }, id: null }); 
app.get('/mcp', requireAuth, notAllowed); 
app.delete('/mcp', requireAuth, notAllowed);

app.listen(config.port, () => { 
  console.log('-----------------------------------------------------------'); 
  console.log(`Servidor MCP a correr na porta ${config.port}`); 
  console.log(`URL do servidor (Grok):     ${config.baseUrl}/mcp`); 
  console.log(`Endpoint de Autorização:    ${config.baseUrl}/oauth/authorize`); 
  console.log(`Endpoint do Token:          ${config.baseUrl}/oauth/token`); 
  console.log(`Escopos:                    ${config.scopes.join(' ')}`); 
  console.log(`Redirect URIs aceites:      ${config.redirectUris.join(', ')}`); 
  console.log('-----------------------------------------------------------'); 
}); 
