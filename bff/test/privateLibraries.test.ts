// Who a private library is hidden from (lib/visibility.ts privateLibrarySplit): everyone but its owner, except that
// admins still see one a member owns. One an admin owns is that admin's alone.
process.env.DATABASE_URL ||= 'postgres://unused:unused@127.0.0.1:1/unused';
process.env.JWT_SECRET ||= 'test-secret-at-least-16-chars';
import test, { before } from 'node:test';
import assert from 'node:assert/strict';

// Imported after the environment is set: env.ts validates DATABASE_URL on load. Nothing here connects.
let privateLibrarySplit: typeof import('../src/lib/visibility').privateLibrarySplit;
before(async () => { ({ privateLibrarySplit } = await import('../src/lib/visibility')); });

const ROWS = [
  { id: 'lib_member', owner_id: 'u_member', owner_admin: false },
  { id: 'lib_admin', owner_id: 'u_admin', owner_admin: true },
  // An owner whose account is gone: no role to read, so not an admin.
  { id: 'lib_gone', owner_id: 'u_gone', owner_admin: false },
];

test('the owner sees their own private library and no one else\'s', () => {
  assert.deepEqual(privateLibrarySplit(ROWS, 'u_member', false), { hidden: ['lib_admin', 'lib_gone'], owned: ['lib_member'] });
});

test('another member sees none of them', () => {
  assert.deepEqual(privateLibrarySplit(ROWS, 'u_other', false), { hidden: ['lib_member', 'lib_admin', 'lib_gone'], owned: [] });
});

test('another admin sees a member\'s, but not an admin\'s', () => {
  assert.deepEqual(privateLibrarySplit(ROWS, 'u_admin2', true), { hidden: ['lib_admin'], owned: [] });
});

test('the owning admin sees their own', () => {
  assert.deepEqual(privateLibrarySplit(ROWS, 'u_admin', true), { hidden: [], owned: ['lib_admin'] });
});
