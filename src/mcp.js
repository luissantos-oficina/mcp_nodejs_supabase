import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'; 
import { z } from 'zod'; 
import { db } from './supabase.js'; 
 
const text = (value) => ({ content: [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }] }); 
const fail = (msg) => ({ content: [{ type: 'text', text: `Erro: ${msg}` }], isError: true }); 
 
// Dados de quem fez login (vêm do middleware requireAuth) 
const userIdOf = (extra) => extra?.authInfo?.extra?.userId; 
const canWrite = (extra) => (extra?.authInfo?.scopes || []).includes('mcp:write'); 
 
export function buildServer() { 
  const server = new McpServer({ name: 'mcp-supabase-notas', version: '1.0.0' }); 
 
  server.registerTool( 
    'listar_notas', 
    { 
      title: 'Listar notas', 
      description: 'Lista as notas mais recentes do utilizador autenticado.', 
      inputSchema: { limite: z.number().int().min(1).max(100).default(20).describe('Quantas notas devolver') }, 
    }, 
    async ({ limite }, extra) => { 
      const { data, error } = await db.from('notas') 
        .select('id, titulo, conteudo, created_at') 
        .eq('user_id', userIdOf(extra)) 
        .order('created_at', { ascending: false }) 
        .limit(limite); 
      return error ? fail(error.message) : text(data); 
    }, 
  ); 
 
  server.registerTool( 
    'procurar_notas', 
    { 
      title: 'Procurar notas', 
      description: 'Procura notas cujo título ou conteúdo contenha o texto indicado.', 
      inputSchema: { texto: z.string().min(1).max(200).describe('Texto a procurar') }, 
    }, 
    async ({ texto }, extra) => { 
      const termo = texto.replace(/[,()%*\\]/g, ' ').trim(); // evita injetar filtros 
      const { data, error } = await db.from('notas') 
        .select('id, titulo, conteudo, created_at') 
        .eq('user_id', userIdOf(extra)) 
        .or(`titulo.ilike.%${termo}%,conteudo.ilike.%${termo}%`) 
        .order('created_at', { ascending: false }) 
        .limit(50); 
      return error ? fail(error.message) : text(data); 
    }, 
  ); 
 
  server.registerTool( 
    'criar_nota', 
    { 
      title: 'Criar nota', 
      description: 'Cria uma nova nota para o utilizador autenticado.', 
      inputSchema: { 
        titulo: z.string().min(1).max(200).describe('Título da nota'), 
        conteudo: z.string().max(10000).optional().describe('Texto da nota'), 
      }, 
    }, 
    async ({ titulo, conteudo }, extra) => { 
      if (!canWrite(extra)) return fail('o token não tem o escopo mcp:write.'); 
      const { data, error } = await db.from('notas') 
        .insert({ user_id: userIdOf(extra), titulo, conteudo: conteudo ?? null }) 
        .select('id, titulo, created_at') 
        .single(); 
      return error ? fail(error.message) : text({ criada: data }); 
    }, 
  ); 
 
  server.registerTool( 
    'apagar_nota', 
    { 
      title: 'Apagar nota', 
      description: 'Apaga uma nota pelo id (apenas notas do próprio utilizador).', 
      inputSchema: { id: z.number().int().positive().describe('Id da nota') }, 
    }, 
    async ({ id }, extra) => { 
      if (!canWrite(extra)) return fail('o token não tem o escopo mcp:write.'); 
      const { data, error } = await db.from('notas') 
        .delete() 
        .eq('id', id) 
        .eq('user_id', userIdOf(extra)) 
        .select('id'); 
      if (error) return fail(error.message); 
      return data.length ? text(`Nota ${id} apagada.`) : fail(`não existe nenhuma nota ${id} tua.`); 
    }, 
  ); 
 
  return server; 
} 