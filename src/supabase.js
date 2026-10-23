import { createClient } from '@supabase/supabase-js'; 
import { config } from './config.js'; 
 
const options = { auth: { persistSession: false, autoRefreshToken: false } }; 
 
// Cliente com a chave SECRETA: ignora o RLS. Usar só no servidor. 
export const db = createClient(config.supabaseUrl, config.supabaseSecretKey, options); 
 
// Cliente com a chave PUBLICÁVEL: só para validar email + palavra-passe no login. 
// É criado de novo em cada login para não partilhar sessões entre utilizadores. 
export function authClient() { 
  return createClient(config.supabaseUrl, config.supabasePublishableKey, options); 
} 