'use client';
// Fork-only: /vault. Once this device can open the vault, it is the ordinary Library filtered to it (the service
// worker lists it as a library); until then, the unlock.
import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import VaultPage from './VaultPage';
import { useDeviceUnlocked, useVaultStatus } from './hooks';

export default function VaultRoute() {
  const { data } = useVaultStatus();
  const unlocked = useDeviceUnlocked();
  const router = useRouter();
  const id = unlocked ? data?.vaults[0]?.id : undefined;
  useEffect(() => { if (id) router.replace(`/library?lib=${encodeURIComponent(id)}`); }, [id, router]);
  return <VaultPage />;
}
