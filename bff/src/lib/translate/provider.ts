import { createHash } from 'node:crypto';

type AuthHeader = 'none' | 'bearer' | 'api-key' | 'x-api-key';

export interface ProviderConfig {
  provider: 'local' | 'openai-compatible' | 'anthropic';
  endpoint: string;
  model: string;
  auth: AuthHeader;
  vision: boolean;
  jsonMode?: boolean;
  apiKey: string | null;
  legacyLlama?: boolean;
}

export function providerConfig(): ProviderConfig {
  const provider = process.env.TRANSLATE_PROVIDER?.trim();
  if (!provider || provider === 'local') {
    const legacy = !provider && process.env.TRANSLATE_ENGINE_URL?.trim();
    if (legacy) return { provider: 'openai-compatible', endpoint: legacy, model: '', auth: 'none', vision: false, apiKey: null, legacyLlama: true };
    return { provider: 'local', endpoint: '', model: '', auth: 'none', vision: false, apiKey: null };
  }
  if (provider !== 'openai-compatible' && provider !== 'anthropic') {
    throw new Error('TRANSLATE_PROVIDER must be local, openai-compatible, or anthropic');
  }
  const defaults = provider === 'anthropic'
    ? { endpoint: 'https://api.anthropic.com/v1/messages', auth: 'x-api-key' }
    : { endpoint: 'https://api.openai.com/v1/chat/completions', auth: 'bearer' };
  const endpoint = process.env.TRANSLATE_PROVIDER_URL?.trim() || defaults.endpoint;
  const url = URL.canParse(endpoint) ? new URL(endpoint) : null;
  if (!url || !['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.hash) {
    throw new Error('TRANSLATE_PROVIDER_URL must be a full HTTP(S) endpoint without embedded credentials or a fragment');
  }
  const model = process.env.TRANSLATE_PROVIDER_MODEL?.trim();
  if (!model) throw new Error('Set TRANSLATE_PROVIDER_MODEL to the model ID or deployment name');
  const auth = process.env.TRANSLATE_PROVIDER_AUTH?.trim() || defaults.auth;
  if (auth !== 'none' && auth !== 'bearer' && auth !== 'api-key' && auth !== 'x-api-key') {
    throw new Error('TRANSLATE_PROVIDER_AUTH must be none, bearer, api-key, or x-api-key');
  }
  const apiKey = auth === 'none' ? null : process.env.TRANSLATE_PROVIDER_API_KEY?.trim() || null;
  if (auth !== 'none' && (!apiKey || url.protocol !== 'https:')) {
    throw new Error('Authenticated translation providers require TRANSLATE_PROVIDER_API_KEY and an HTTPS endpoint');
  }
  return {
    provider, endpoint, model, auth, apiKey,
    vision: process.env.TRANSLATE_PROVIDER_VISION === 'true',
    jsonMode: provider === 'openai-compatible' && process.env.TRANSLATE_PROVIDER_JSON_MODE === 'true',
  };
}

export function providerFingerprint(): string {
  const config = providerConfig();
  if (config.provider === 'local') return 'local';
  return createHash('sha256')
    .update(JSON.stringify([config.provider, config.endpoint, config.model, config.vision, config.jsonMode]))
    .digest('hex').slice(0, 16);
}
