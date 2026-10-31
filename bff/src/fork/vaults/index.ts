// Fork-only: end-to-end encrypted vaults -- the one entry point server.ts calls.
//
// Everything this feature needs on the server lives under src/fork/vaults/, and server.ts (registerE2E) is the only
// upstream file that knows about it. A series moved into a vault leaves the library entirely (move.ts), so no upstream
// query, scan or download ever meets vault content. Its tables are its own (schema.ts), created here rather than in
// lib/migrate.ts. Nothing runs in the background.
//
// E2E_LIBRARIES=0 turns it off: no tables are created and no route is registered.
import type { FastifyInstance } from 'fastify';
import { migrateE2E } from './schema';
import e2eRoutes from './routes';

export const e2eEnabled = (): boolean => !/^(0|false|off|no)$/i.test((process.env.E2E_LIBRARIES || '').trim());

export async function registerE2E(app: FastifyInstance): Promise<void> {
  if (!e2eEnabled()) return;
  await migrateE2E();
  await app.register(e2eRoutes);
}
