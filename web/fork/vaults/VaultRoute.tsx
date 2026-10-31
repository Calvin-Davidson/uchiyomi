'use client';
// Fork-only: /vault. Once this device can open the vault, it is the ordinary Library page fixed to the vault
// (shelf.ts; the service worker answers for its series). Until then, the unlock.
import LibraryPage from '@/app/library/page';
import VaultPage from './VaultPage';
import { useDeviceUnlocked, useVaultStatus } from './hooks';

export default function VaultRoute() {
  const { data } = useVaultStatus();
  const unlocked = useDeviceUnlocked();
  return data?.vaults.length && unlocked ? <LibraryPage /> : <VaultPage />;
}
