import assert from 'node:assert/strict';
import { test } from 'node:test';
import { zipSync } from 'fflate';

import { memoryR2 } from '../test/support/env';
import { ARCHIVE_PART_BYTES, R2PartWriter, R2ZipReader } from './backup-zip';

const encoder = new TextEncoder();
const text = async (stream: ReadableStream<Uint8Array>) => new Response(stream).text();

test('the part writer uploads same-size parts and a shorter last one, as R2 requires', async () => {
  const { binding, objects } = memoryR2();
  const writer = await R2PartWriter.open(binding, 'archive.zip', 'application/zip');
  // Uneven chunks that straddle part boundaries: two and a half parts in all.
  const chunk = new Uint8Array(ARCHIVE_PART_BYTES / 4 + 3).fill(7);
  const chunks = Math.ceil((ARCHIVE_PART_BYTES * 2.5) / chunk.byteLength);
  for (let index = 0; index < chunks; index++) {
    writer.write(chunk);
    await writer.flush();
  }
  const object = await writer.close();
  assert.equal(object.size, chunk.byteLength * chunks);
  assert.ok(objects.get('archive.zip')!.bytes.every((byte) => byte === 7));
});

test('an empty write completes as one empty part', async () => {
  const { binding, objects } = memoryR2();
  await (await R2PartWriter.open(binding, 'empty.zip', 'application/zip')).close();
  assert.equal(objects.get('empty.zip')!.bytes.byteLength, 0);
});

test('the reader finds stored and deflated entries through the central directory', async () => {
  const { binding } = memoryR2();
  const archive = zipSync({
    'manifest.json': [encoder.encode('{"formatVersion":3}'), { level: 0 }],
    'db/0001.json': [encoder.encode('{"users":[]}'.repeat(200)), { level: 6 }],
    // An extra field makes the data start later than a bare header says.
    'attachments/c/a.bin': [encoder.encode('file'), { level: 0, extra: { 0x5455: new Uint8Array(5) } }],
  });
  await binding.put('archive.zip', archive);
  const zip = (await R2ZipReader.open(binding, 'archive.zip'))!;
  assert.deepEqual(
    zip.entries.map(({ name, size }) => [name, size]),
    [
      ['manifest.json', 19],
      ['db/0001.json', 2400],
      ['attachments/c/a.bin', 4],
    ],
  );
  const [manifest, slice, file] = zip.entries;
  assert.equal(await text(await zip.stream(manifest)), '{"formatVersion":3}');
  assert.equal(await text(await zip.stream(slice)), '{"users":[]}'.repeat(200));
  assert.equal(await text(await zip.stream(file)), 'file');
  await assert.rejects(zip.bytes(slice, 100, 'too large'), { message: 'too large' });
  assert.equal(await R2ZipReader.open(binding, 'missing.zip'), null);
});

test('the reader finds the end record behind an archive comment', async () => {
  const { binding } = memoryR2();
  const archive = zipSync({ 'manifest.json': [encoder.encode('{}'), { level: 0 }] });
  const comment = encoder.encode('written by another tool');
  const commented = new Uint8Array(archive.byteLength + comment.byteLength);
  commented.set(archive);
  commented.set(comment, archive.byteLength);
  new DataView(commented.buffer).setUint16(archive.byteLength - 2, comment.byteLength, true);
  await binding.put('commented.zip', commented);
  const zip = (await R2ZipReader.open(binding, 'commented.zip'))!;
  assert.equal(await text(await zip.stream(zip.entries[0])), '{}');
});

test('the reader refuses what is not a readable ZIP32 archive', async () => {
  const { binding } = memoryR2();
  const archive = zipSync({ 'manifest.json': [encoder.encode('{}'), { level: 0 }] });
  const endOffset = archive.byteLength - 22;
  const variants: Array<[Uint8Array, string]> = [
    [encoder.encode('not a zip archive at all, just text'), 'Invalid backup archive'],
    [archive.slice(0, 10), 'Invalid backup archive'],
  ];
  const encrypted = archive.slice();
  const directoryOffset = new DataView(encrypted.buffer).getUint32(endOffset + 16, true);
  new DataView(encrypted.buffer).setUint16(directoryOffset + 8, 1, true);
  variants.push([encrypted, 'Backup archive entries are encrypted']);
  const zip64 = archive.slice();
  new DataView(zip64.buffer).setUint32(endOffset + 16, 0xffff_ffff, true);
  variants.push([zip64, 'Backup archive uses ZIP64, which restore does not read']);
  for (const [bytes, message] of variants) {
    await binding.put('bad.zip', bytes);
    await assert.rejects(R2ZipReader.open(binding, 'bad.zip'), { message });
  }
});
