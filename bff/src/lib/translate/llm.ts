import { spawn, type ChildProcess } from 'node:child_process';
import net from 'node:net';
import os from 'node:os';
import type { ProviderConfig } from './provider';

/** What the translation model runs from: the downloaded llama-server and model, or a llama.cpp-compatible URL. */
export interface ModelRun {
  /** llama-server from the download; absent when `url` names a server that is already running. */
  bin?: string;
  model?: string;
  /** The vision projector: with it the model can be shown the page (the large model only). */
  mmproj?: string;
  /** The large model carries its own draft heads (multi-token prediction): speculative decoding at no extra memory. */
  mtp?: boolean;
  threads: number;
  /** A configured hosted model provider. Its API key remains server-side. */
  provider?: ProviderConfig;
  /** Existing llama.cpp-compatible endpoint, retained for TRANSLATE_ENGINE_URL installs. */
  url?: string;
}

/** Loading 18 GB from a hard disk took 90 s on the owner's server: the first page waits this long at most. */
const LOAD_TIMEOUT_MS = 5 * 60_000;

const freePort = () => new Promise<number>((resolve, reject) => {
  const s = net.createServer();
  s.unref();
  s.on('error', reject);
  s.listen(0, '127.0.0.1', () => { const { port } = s.address() as net.AddressInfo; s.close(() => resolve(port)); });
});

/**
 * llama-server as a child of the server: started on the first page, kept while pages come, stopped by the engine when
 * idle. It listens on 127.0.0.1 only, on a free port, and runs at low priority so reading and downloading stay quick.
 */
export class TranslationModel {
  private child: ChildProcess | null = null;
  private base: string | null = null;
  private starting: Promise<string> | null = null;
  private stderr = '';

  constructor(private readonly run: ModelRun) {}

  get vision(): boolean { return this.run.provider?.vision ?? !!this.run.mmproj; }
  get running(): boolean { return !!this.base && (!!this.run.url || (!!this.child && this.child.exitCode == null)); }

  private async start(): Promise<string> {
    if (this.base && this.running) return this.base;
    if (this.run.provider) return '';
    if (this.run.url) return (this.base = this.run.url.replace(/\/+$/, ''));
    if (this.starting) return this.starting;
    this.starting = (async () => {
      if (!this.run.bin || !this.run.model) throw new Error('the translation engine is not installed');
      const port = await freePort();
      const args = ['-m', this.run.model, '--host', '127.0.0.1', '--port', String(port),
        '-t', String(this.run.threads), '-tb', String(this.run.threads), '-c', '8192', '--parallel', '1', '--no-webui'];
      if (this.run.mmproj) args.push('--mmproj', this.run.mmproj);
      if (this.run.mtp) args.push('--spec-type', 'draft-mtp');
      // Nothing of the server's environment goes along: the model needs none of it, the database URL least of all.
      const child = spawn(this.run.bin, args, { env: { PATH: process.env.PATH ?? '' }, stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true });
      try { if (child.pid) os.setPriority(child.pid, 15); } catch { /* not permitted: normal priority */ }
      this.stderr = '';
      child.stderr?.on('data', (d: Buffer) => { this.stderr = (this.stderr + d.toString()).slice(-4000); });
      // ⚠️ Listened to, always: an 'error' with no listener (a binary that cannot be run) would take the server down with it.
      let failed: Error | null = null;
      child.on('error', (e) => { failed = e; });
      this.child = child;
      const base = `http://127.0.0.1:${port}`;
      const deadline = Date.now() + LOAD_TIMEOUT_MS;
      for (;;) {
        if (failed) { this.child = null; throw new Error(`the translation model stopped while loading: ${(failed as Error).message}`); }
        if (child.exitCode != null || child.signalCode) throw new Error(`the translation model stopped while loading: ${this.lastError()}`);
        try {
          const r = await fetch(`${base}/health`, { signal: AbortSignal.timeout(3000) });
          if (r.ok) break;
        } catch { /* still loading */ }
        if (Date.now() > deadline) { this.stop(); throw new Error('the translation model took too long to load'); }
        await new Promise((r) => setTimeout(r, 1000));
      }
      return (this.base = base);
    })();
    try { return await this.starting; } finally { this.starting = null; }
  }

  private lastError(): string {
    const lines = this.stderr.trim().split('\n').filter((l) => /error|failed|cannot|unable/i.test(l));
    return (lines.pop() ?? this.stderr.trim().split('\n').pop() ?? 'no output').slice(0, 300);
  }

  /** One chat completion; `content` is the user turn (text, or text and the page image). */
  async chat(system: string, content: unknown, schema: object, timeoutMs = 10 * 60_000): Promise<{ text: string; timings: Record<string, number> }> {
    const base = await this.start();
    const hosted = this.run.provider;
    if (hosted?.provider === 'anthropic') {
      const parts = anthropicParts(content);
      const headers: Record<string, string> = {
        'content-type': 'application/json',
        'anthropic-version': '2023-06-01',
      };
      if (hosted.apiKey) {
        if (hosted.auth === 'bearer') headers.authorization = `Bearer ${hosted.apiKey}`;
        else if (hosted.auth === 'api-key') headers['api-key'] = hosted.apiKey;
        else if (hosted.auth === 'x-api-key') headers['x-api-key'] = hosted.apiKey;
      }
      const response = await fetch(hosted.endpoint, {
        method: 'POST', headers, redirect: 'error',
        body: JSON.stringify({
          model: hosted.model, system, messages: [{ role: 'user', content: parts }],
          temperature: 0.2, max_tokens: 2000,
          output_config: { format: { type: 'json_schema', schema: anthropicSchema(schema) } },
        }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!response.ok) throw new Error(`the translation provider answered ${response.status}`);
      const result = await response.json() as { content?: Array<{ type?: string; text?: string }> };
      const text = (result.content ?? []).filter((part) => part.type === 'text').map((part) => part.text ?? '').join('');
      if (!text) throw new Error('the translation provider gave no answer');
      return { text, timings: {} };
    }

    const endpoint = hosted ? hosted.endpoint : `${base}/v1/chat/completions`;
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (hosted?.apiKey) {
      if (hosted.auth === 'bearer') headers.authorization = `Bearer ${hosted.apiKey}`;
      else if (hosted.auth === 'api-key') headers['api-key'] = hosted.apiKey;
      else if (hosted.auth === 'x-api-key') headers['x-api-key'] = hosted.apiKey;
    }
    const body: Record<string, unknown> = {
      messages: [{ role: 'system', content: system }, { role: 'user', content }],
      temperature: 0.2, max_tokens: 2000,
      response_format: hosted?.jsonMode
        ? { type: 'json_object' }
        : { type: 'json_schema', json_schema: hosted
          ? { name: 'page', schema: strictSchema(schema), strict: true }
          : { name: 'page', schema } },
    };
    if (hosted) body.model = hosted.model;
    else {
      // Existing local/llama.cpp path has relied on prompt caching and disabled chain-of-thought in the template.
      body.cache_prompt = true;
      body.chat_template_kwargs = { enable_thinking: false };
    }
    const r = await fetch(endpoint, {
      method: 'POST',
      headers, redirect: 'error', body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!r.ok) throw new Error(`the translation provider answered ${r.status}`);
    const j = await r.json() as { choices?: { message?: { content?: string } }[]; timings?: Record<string, number> };
    const text = j.choices?.[0]?.message?.content;
    if (typeof text !== 'string') throw new Error('the translation model gave no answer');
    return { text, timings: j.timings ?? {} };
  }

  stop(): void {
    const c = this.child;
    this.child = null; this.base = null;
    if (c && c.exitCode == null) c.kill();
  }
}

/** Convert the pipeline's OpenAI-style text/data-URL image parts to Anthropic's Messages content blocks. */
function anthropicParts(content: unknown): Array<Record<string, unknown>> {
  if (typeof content === 'string') return [{ type: 'text', text: content }];
  if (!Array.isArray(content)) throw new Error('the translation request has an unsupported content shape');
  const parts: Array<Record<string, unknown>> = [];
  for (const raw of content) {
    if (!raw || typeof raw !== 'object') continue;
    const item = raw as { type?: string; text?: string; image_url?: { url?: string } };
    if (item.type === 'text' && typeof item.text === 'string') parts.push({ type: 'text', text: item.text });
    if (item.type === 'image_url' && typeof item.image_url?.url === 'string') {
      const match = /^data:(image\/(?:jpeg|png|gif|webp));base64,([A-Za-z0-9+/=]+)$/.exec(item.image_url.url);
      if (!match) throw new Error('the translation page image has an unsupported format');
      parts.push({ type: 'image', source: { type: 'base64', media_type: match[1], data: match[2] } });
    }
  }
  if (!parts.length) throw new Error('the translation request has no content');
  return parts;
}

/** Anthropic's schema subset omits maxItems and permits minItems only at 0 or 1; parseAnswer checks exact counts. */
function anthropicSchema(schema: object): object {
  return mapSchema(schema, 'anthropic');
}

/** OpenAI strict structured outputs require closed objects and every field required (answerSchema already does this). */
function strictSchema(schema: object): object {
  return mapSchema(schema, 'strict');
}

function mapSchema(value: unknown, mode: 'anthropic' | 'strict'): any {
  if (Array.isArray(value)) return value.map((item) => mapSchema(item, mode));
  if (!value || typeof value !== 'object') return value;
  const source = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(source)) {
    if (mode === 'anthropic' && (key === 'maxItems' || (key === 'minItems' && typeof item === 'number' && item > 1))) continue;
    out[key] = mapSchema(item, mode);
  }
  if (source.type === 'object') out.additionalProperties = false;
  return out;
}
