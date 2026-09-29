import { z } from 'zod';
import { LIMITS } from '../config/limits';
import { getOrm, type Orm } from '../db/client';
import { ciphers as cipherTable, folders as folderTable } from '../db/schema';
import { notifyUserVaultSync } from '../durable/notifications-hub';
import type {
  Cipher,
  CipherBankAccount,
  CipherDriversLicense,
  CipherPassport,
  Folder,
  PasswordHistory,
} from '../types';
import { readActingDeviceIdentifier } from '../utils/device';
import { errorResponse, type BodyContext } from '../utils/response';
import {
  normalizeCipherLoginForStorage,
  normalizeCipherSshKeyForCompatibility,
  validateCipherEncryptedFieldsForCompatibility,
} from './ciphers';
import { folderRepo } from '../services/storage-folder-repo';
import { revisionRepo } from '../services/storage-revision-repo';

const orNull = <T extends z.ZodType>(schema: T) => schema.nullish().transform((value) => value ?? null);
const list = <T extends z.ZodType>(item: T) =>
  z
    .array(item)
    .nullish()
    .transform((items) => items ?? []);
const encString = orNull(z.string());
const optionalId = z
  .string()
  .nullish()
  .transform((id) => id?.trim() || null);
// Shapes the cipher endpoints own; validateCipherEncryptedFieldsForCompatibility checks their fields.
const clientObject = <T>() => orNull(z.custom<T>((value) => typeof value === 'object'));

// Bitwarden's ImportCiphersRequestModel. jsonBody folds PascalCase keys to camelCase; cipher entries
// keep unknown keys so new client fields persist, and absent fields default as the create endpoint's.
export const CiphersImportBody = z.object({
  ciphers: list(
    z.looseObject({
      id: optionalId,
      type: z.number(),
      folderId: optionalId,
      name: z
        .string()
        .nullish()
        .transform((name) => name ?? 'Untitled'),
      notes: encString,
      favorite: z
        .boolean()
        .nullish()
        .transform((favorite) => favorite ?? false),
      reprompt: z
        .number()
        .nullish()
        .transform((reprompt) => reprompt ?? 0),
      key: encString,
      login: orNull(
        z.looseObject({
          username: encString,
          password: encString,
          uris: orNull(z.array(z.looseObject({ uri: encString, uriChecksum: encString, match: orNull(z.number()) }))),
          totp: encString,
          autofillOnPageLoad: orNull(z.boolean()),
          uri: encString,
          passwordRevisionDate: encString,
        }),
      ),
      card: orNull(
        z.looseObject({
          cardholderName: encString,
          brand: encString,
          number: encString,
          expMonth: encString,
          expYear: encString,
          code: encString,
        }),
      ),
      identity: orNull(
        z.looseObject({
          title: encString,
          firstName: encString,
          middleName: encString,
          lastName: encString,
          address1: encString,
          address2: encString,
          address3: encString,
          city: encString,
          state: encString,
          postalCode: encString,
          country: encString,
          company: encString,
          email: encString,
          phone: encString,
          ssn: encString,
          username: encString,
          passportNumber: encString,
          licenseNumber: encString,
        }),
      ),
      secureNote: orNull(z.looseObject({ type: z.number() })),
      sshKey: z.unknown().optional(),
      bankAccount: clientObject<CipherBankAccount>(),
      driversLicense: clientObject<CipherDriversLicense>(),
      passport: clientObject<CipherPassport>(),
      fields: orNull(
        z.array(z.looseObject({ name: encString, value: encString, type: z.number(), linkedId: orNull(z.number()) })),
      ),
      passwordHistory: clientObject<PasswordHistory[]>(),
    }),
  ),
  folders: list(z.object({ name: z.string().nullish() })),
  folderRelationships: list(z.object({ key: z.number(), value: z.number() })),
});

async function runOrmBatch(
  orm: Orm,
  statements: Array<{ execute: () => Promise<unknown> }>,
  chunkSize: number,
): Promise<void> {
  for (let offset = 0; offset < statements.length; offset += chunkSize) {
    const chunk = statements.slice(offset, offset + chunkSize);
    if (!chunk.length) continue;
    await orm.batch(chunk as unknown as Parameters<Orm['batch']>[0]);
  }
}

// POST /api/ciphers/import - Bitwarden client import endpoint
export async function handleCiphersImport(c: BodyContext<typeof CiphersImportBody>): Promise<Response> {
  const { userId } = c.var;
  const orm = getOrm(c.env.DB);
  const url = new URL(c.req.raw.url);
  const returnCipherMap = url.searchParams.get('returnCipherMap') === '1';

  const body = c.req.valid('json');
  const { folders, ciphers, folderRelationships } = body;

  if (folders.length + ciphers.length > LIMITS.performance.importItemLimit) {
    return errorResponse(c, `Import exceeds maximum of ${LIMITS.performance.importItemLimit} items`, 400);
  }

  const now = new Date().toISOString();
  const batchChunkSize = LIMITS.performance.bulkMoveChunkSize;

  // Create folders and build index -> id mapping
  const folderIdMap = new Map<number, string>();
  const folderRows: Folder[] = [];

  for (let i = 0; i < folders.length; i++) {
    const folderId = crypto.randomUUID();
    folderIdMap.set(i, folderId);

    const folder: Folder = {
      id: folderId,
      userId: userId,
      name: folders[i].name || 'Folder',
      createdAt: now,
      updatedAt: now,
    };

    folderRows.push(folder);
  }

  if (folderRows.length > 0) {
    await runOrmBatch(
      orm,
      folderRows.map((folder) =>
        orm
          .insert(folderTable)
          .values(folder)
          .onConflictDoUpdate({
            target: folderTable.id,
            set: { userId: folder.userId, name: folder.name, updatedAt: folder.updatedAt },
          }),
      ),
      batchChunkSize,
    );
  }

  // Build cipher index -> folder id mapping from relationships
  const cipherFolderMap = new Map<number, string>();
  for (const rel of folderRelationships) {
    const folderId = folderIdMap.get(rel.value);
    if (folderId) {
      cipherFolderMap.set(rel.key, folderId);
    }
  }
  const existingFolderIds = new Set((await folderRepo(c.env.DB).getAllFolders(userId)).map((folder) => folder.id));

  // Create ciphers
  const cipherRows: Cipher[] = [];
  const cipherMapRows: Array<{ index: number; sourceId: string | null; id: string }> = [];
  for (let i = 0; i < ciphers.length; i++) {
    const imported = ciphers[i];
    const folderId =
      cipherFolderMap.get(i) ||
      (imported.folderId && existingFolderIds.has(imported.folderId) ? imported.folderId : null);
    const cipher: Cipher = {
      ...imported,
      id: crypto.randomUUID(),
      userId: userId,
      folderId: folderId,
      login: normalizeCipherLoginForStorage(imported.login),
      sshKey: normalizeCipherSshKeyForCompatibility(imported.sshKey ?? null),
      createdAt: now,
      updatedAt: now,
      archivedAt: null,
      deletedAt: null,
    };
    const compatibilityError = validateCipherEncryptedFieldsForCompatibility(cipher);
    if (compatibilityError) {
      return errorResponse(c, `Cipher ${i + 1}: ${compatibilityError}`, 400);
    }

    cipherRows.push(cipher);
    cipherMapRows.push({ index: i, sourceId: imported.id, id: cipher.id });
  }

  if (cipherRows.length > 0) {
    const cipherStatements = cipherRows.map((cipher) => {
      const values = {
        id: cipher.id,
        userId: cipher.userId,
        organizationId: null,
        type: Number(cipher.type) || 1,
        folderId: cipher.folderId,
        name: cipher.name,
        notes: cipher.notes,
        favorite: cipher.favorite ? 1 : 0,
        data: JSON.stringify(cipher),
        reprompt: cipher.reprompt,
        key: cipher.key,
        createdAt: cipher.createdAt,
        updatedAt: cipher.updatedAt,
        archivedAt: cipher.archivedAt,
        deletedAt: cipher.deletedAt,
      };
      return orm
        .insert(cipherTable)
        .values(values)
        .onConflictDoUpdate({
          target: cipherTable.id,
          set: {
            userId: values.userId,
            type: values.type,
            folderId: values.folderId,
            name: values.name,
            notes: values.notes,
            favorite: values.favorite,
            data: values.data,
            reprompt: values.reprompt,
            key: values.key,
            updatedAt: values.updatedAt,
            archivedAt: values.archivedAt,
            deletedAt: values.deletedAt,
          },
        });
    });
    await runOrmBatch(orm, cipherStatements, batchChunkSize);
  }

  // Update revision date
  const revisionDate = await revisionRepo(c.env.DB).updateRevisionDate(userId);
  notifyUserVaultSync(c.env, userId, revisionDate, readActingDeviceIdentifier(c.req.raw));

  if (returnCipherMap) {
    return c.json({
      object: 'import-result',
      cipherMap: cipherMapRows,
    });
  }

  return new Response(null, { status: 200 });
}
