export const encryptedSeriesId = (id: string) => id.startsWith('s_e2ee_');
export const encryptedBookId = (id: string) => id.startsWith('b_e2ee_');
export const ENCRYPTED_MEDIA_TYPE = 'application/vnd.yomi.encrypted-page';
export const ENCRYPTED_PAGE_MAGIC = Buffer.from('YOMIE2E1');
export const isEncryptedPage = (bytes: Buffer, size = bytes.length) =>
  size > ENCRYPTED_PAGE_MAGIC.length + 12 + 16 + 1 &&
  bytes.subarray(0, ENCRYPTED_PAGE_MAGIC.length).equals(ENCRYPTED_PAGE_MAGIC);
