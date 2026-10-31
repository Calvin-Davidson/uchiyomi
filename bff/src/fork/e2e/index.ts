// Fork-only: end-to-end encrypted vaults -- the one entry point server.ts calls.
//
// Everything this feature needs on the server lives under src/fork/e2e/. Upstream files carry only small,
// `fork-only`-marked calls into it: server.ts (registerE2E), lib/visibility.ts (who sees a vault), lib/ownedCatalog.ts
// (the libraries list), lib/downloader.ts (seal before write), lib/library.ts (sealed page sizes) and routes/images.ts
// (serve sealed pages). Its tables are its own (schema.ts), created here rather than in lib/migrate.ts.
//
// E2E_LIBRARIES=0 turns it off: no tables are created, no route is registered, and every hook is a no-op (no vaults
// are loaded, so vaults.ts hides nothing and seal/serve find no vault).
import type { FastifyInstance } from 'fastify';
import { migrateE2E } from './schema';
import { loadVaults } from './vaults';
import { sweepVaults } from './seal';
import e2eRoutes from './routes';

export const e2eEnabled = (): boolean => !/^(0|false|off|no)$/i.test((process.env.E2E_LIBRARIES || '').trim());

/** How often every vault is checked for chapter files written by a path that does not seal (an import, a completion). */
const SWEEP_MS = 10 * 60 * 1000;

export async function registerE2E(app: FastifyInstance): Promise<void> {
  if (!e2eEnabled()) return;
  await migrateE2E();
  await loadVaults();
  await app.register(e2eRoutes);
  const sweep = () => sweepVaults()
    .then((r) => { if (r.sealed || r.failed) app.log.info(`e2e: sealed ${r.sealed} chapter file(s), ${r.failed} could not be`); })
    .catch((e) => app.log.warn(`e2e: sweep failed: ${(e as Error)?.message || e}`));
  setTimeout(sweep, 30_000).unref();
  setInterval(sweep, SWEEP_MS).unref();
}
