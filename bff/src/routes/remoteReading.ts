import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { authenticate, userIdOf } from '../lib/auth';
import { remotePosition, writeRemoteReading } from '../lib/remoteReading';

const params = z.object({ digest: z.string().regex(/^[a-f0-9]{64}$/) });
const title = z.string().trim().min(1).max(500).regex(/^[^\u0000-\u001f]*$/);
const body = z.strictObject({
  title, seriesTitle: title, page: z.number().int().min(1).max(1000), pages: z.number().int().min(1).max(1000),
  eventId: z.uuid(), at: z.number().int().positive().max(8640000000000000),
  deviceId: z.string().max(128).optional(), incognito: z.boolean().optional(),
}).refine(w => w.page <= w.pages);

export async function remoteReadingRoutes(app: FastifyInstance) {
  app.addHook('preHandler', authenticate);
  app.addHook('onSend', async (_req, reply) => { reply.header('Cache-Control','private, no-store'); reply.header('Vary','*'); reply.header('X-Uchiyomi-Private','1'); });
  app.get('/api/personal/remote-books/:digest/progress', async (req,reply) => {
    const parsed = params.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({error:'bad_request'});
    return remotePosition(userIdOf(req),parsed.data.digest);
  });
  app.put('/api/personal/remote-books/:digest/progress', {bodyLimit:8192}, async (req,reply) => {
    const parsed = params.safeParse(req.params), input = body.safeParse(req.body);
    if (!parsed.success || !input.success) return reply.code(400).send({error:'bad_request'});
    return writeRemoteReading(userIdOf(req),parsed.data.digest,input.data);
  });
}
