// Fork-only: end-to-end encrypted ("private") libraries -- the one entry point server.ts calls.
//
// Everything this feature needs lives under src/fork/e2e/, so an upstream merge only ever meets the two lines
// in server.ts that import and call registerE2E(). Its tables are its own (schema.ts), created here rather than in
// lib/migrate.ts; its routes are a plugin of their own (routes.ts); its files live under E2E_DIR (store.ts).
//
// E2E_LIBRARIES=0 turns the whole feature off: no tables are created and no route is registered.
import type { FastifyInstance } from 'fastify';
import { migrateE2E } from './schema';
import e2eRoutes, { sweepPendingItems } from './routes';

export const e2eEnabled = (): boolean => !/^(0|false|off|no)$/i.test((process.env.E2E_LIBRARIES || '').trim());

const SWEEP_MS = 6 * 60 * 60 * 1000;

export async function registerE2E(app: FastifyInstance): Promise<void> {
  if (!e2eEnabled()) return;
  await migrateE2E();
  await app.register(e2eRoutes);
  const sweep = () => sweepPendingItems()
    .then((n) => { if (n) app.log.info(`e2e: dropped ${n} abandoned upload(s)`); })
    .catch((e) => app.log.warn(`e2e: sweep failed: ${(e as Error)?.message || e}`));
  setTimeout(sweep, 60_000).unref();
  setInterval(sweep, SWEEP_MS).unref();
}
