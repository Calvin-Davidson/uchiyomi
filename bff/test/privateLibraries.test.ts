// Who a private library is hidden from (lib/visibility.ts privateLibrarySplit): everyone but its owner, admins included.
process.env.DATABASE_URL ||= 'postgres://unused:unused@127.0.0.1:1/unused';
process.env.JWT_SECRET ||= 'test-secret-at-least-16-chars';
import test, { before } from 'node:test';
import assert from 'node:assert/strict';

// Imported after the environment is set: env.ts validates DATABASE_URL on load. Nothing here connects.
let privateLibrarySplit: typeof import('../src/lib/visibility').privateLibrarySplit;
before(async () => { ({ privateLibrarySplit } = await import('../src/lib/visibility')); });

const ROWS = [
  { id: 'lib_member', owner_id: 'u_member' },
  { id: 'lib_admin', owner_id: 'u_admin' },
  // An owner whose account is gone: no one's.
  { id: 'lib_gone', owner_id: 'u_gone' },
];

test('the owner sees their own private library and no one else\'s', () => {
  assert.deepEqual(privateLibrarySplit(ROWS, 'u_member'), { hidden: ['lib_admin', 'lib_gone'], owned: ['lib_member'] });
});

test('anyone else, an admin included, sees none of them', () => {
  assert.deepEqual(privateLibrarySplit(ROWS, 'u_other'), { hidden: ['lib_member', 'lib_admin', 'lib_gone'], owned: [] });
});

test('the owning admin sees their own', () => {
  assert.deepEqual(privateLibrarySplit(ROWS, 'u_admin'), { hidden: ['lib_member', 'lib_gone'], owned: ['lib_admin'] });
});
