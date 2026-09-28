// Zip archives in R2 without holding them in memory: a writer that uploads fflate's output as R2 multipart parts,
// and a reader that finds entries through the central directory and fetches each with one range read.
// ZIP32 only: an archive stays under 4 GiB and 65,535 entries.

const BYTES_PER_MIB = 1024 * 1024;
// R2 needs every part but the last to be the same size, and at least 5 MiB.
export const ARCHIVE_PART_BYTES = 8 * BYTES_PER_MIB;
export const MAX_ZIP32_BYTES = 0xffff_ffff;
export const MAX_ZIP32_ENTRIES = 0xffff;

const END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054b50;
const CENTRAL_DIRECTORY_SIGNATURE = 0x02014b50;
const LOCAL_HEADER_SIGNATURE = 0x04034b50;
const END_OF_CENTRAL_DIRECTORY_BYTES = 22;
const MAX_ZIP_COMMENT_BYTES = 0xffff;
const CENTRAL_DIRECTORY_ENTRY_BYTES = 46;
const LOCAL_HEADER_BYTES = 30;
const ENCRYPTED_FLAG = 0x1;
const STORED = 0;
const DEFLATED = 8;

export interface ZipEntry {
  name: string;
  method: number;
  compressedSize: number;
  size: number;
  // Where the entry's local header starts, and where the next record does.
  offset: number;
  end: number;
}

// Streams bytes into one R2 object. Writes buffer until a whole part is ready; flush() uploads the ready parts.
export class R2PartWriter {
  private buffered: Uint8Array[] = [];
  private bufferedBytes = 0;
  private written = 0;
  private readonly parts: R2UploadedPart[] = [];

  private constructor(private readonly upload: R2MultipartUpload) {}

  static async open(bucket: R2Bucket, key: string, contentType: string): Promise<R2PartWriter> {
    return new R2PartWriter(await bucket.createMultipartUpload(key, { httpMetadata: { contentType } }));
  }

  write(chunk: Uint8Array): void {
    this.written += chunk.byteLength;
    if (this.written > MAX_ZIP32_BYTES) throw new Error('Backup archive would exceed 4 GiB');
    this.buffered.push(chunk);
    this.bufferedBytes += chunk.byteLength;
  }

  async flush(): Promise<void> {
    while (this.bufferedBytes >= ARCHIVE_PART_BYTES) await this.uploadPart(ARCHIVE_PART_BYTES);
  }

  async close(): Promise<R2Object> {
    await this.flush();
    // A multipart upload completes with at least one part, which may be empty when it is the only one.
    if (this.bufferedBytes || !this.parts.length) await this.uploadPart(this.bufferedBytes);
    return this.upload.complete(this.parts);
  }

  async abort(): Promise<void> {
    await this.upload.abort();
  }

  private async uploadPart(length: number): Promise<void> {
    const part = new Uint8Array(length);
    let filled = 0;
    while (filled < length) {
      const chunk = this.buffered[0];
      const taken = Math.min(chunk.byteLength, length - filled);
      part.set(chunk.subarray(0, taken), filled);
      filled += taken;
      if (taken === chunk.byteLength) this.buffered.shift();
      else this.buffered[0] = chunk.subarray(taken);
    }
    this.bufferedBytes -= length;
    this.parts.push(await this.upload.uploadPart(this.parts.length + 1, part));
  }
}

// Reads a byte stream in exact amounts.
class ByteReader {
  private pending: Uint8Array = new Uint8Array(0);

  constructor(private readonly reader: ReadableStreamDefaultReader<Uint8Array>) {}

  async take(count: number): Promise<Uint8Array> {
    while (this.pending.byteLength < count) {
      const { done, value } = await this.reader.read();
      if (done) throw new Error('Backup archive entry is truncated');
      const joined = new Uint8Array(this.pending.byteLength + value.byteLength);
      joined.set(this.pending);
      joined.set(value, this.pending.byteLength);
      this.pending = joined;
    }
    const taken = this.pending.subarray(0, count);
    this.pending = this.pending.subarray(count);
    return taken;
  }

  // The next count bytes as a stream; the rest of the source is cancelled once they are through.
  stream(count: number): ReadableStream<Uint8Array> {
    let remaining = count;
    return new ReadableStream<Uint8Array>({
      pull: async (controller) => {
        if (!remaining) {
          controller.close();
          await this.reader.cancel();
          return;
        }
        if (!this.pending.byteLength) {
          const { done, value } = await this.reader.read();
          if (done) throw new Error('Backup archive entry is truncated');
          this.pending = value;
        }
        const chunk = this.pending.subarray(0, remaining);
        this.pending = this.pending.subarray(chunk.byteLength);
        remaining -= chunk.byteLength;
        controller.enqueue(chunk);
      },
      cancel: (reason) => this.reader.cancel(reason),
    });
  }
}

export class R2ZipReader {
  private constructor(
    private readonly bucket: R2Bucket,
    private readonly key: string,
    readonly size: number,
    readonly entries: ZipEntry[],
  ) {}

  static async open(bucket: R2Bucket, key: string): Promise<R2ZipReader | null> {
    const head = await bucket.head(key);
    if (!head) return null;
    const read = async (offset: number, length: number) => {
      const object = await bucket.get(key, { range: { offset, length } });
      if (!object) throw new Error('Backup archive changed while it was read');
      return new DataView(await object.arrayBuffer());
    };
    // The end record closes the archive, after a comment of up to 64 KiB; most archives have none.
    const findEnd = async (window: number) => {
      const start = Math.max(0, head.size - window);
      const tail = await read(start, head.size - start);
      for (let at = tail.byteLength - END_OF_CENTRAL_DIRECTORY_BYTES; at >= 0; at--)
        if (tail.getUint32(at, true) === END_OF_CENTRAL_DIRECTORY_SIGNATURE)
          return new DataView(tail.buffer, tail.byteOffset + at, END_OF_CENTRAL_DIRECTORY_BYTES);
      return null;
    };
    if (head.size < END_OF_CENTRAL_DIRECTORY_BYTES) throw new Error('Invalid backup archive');
    const end =
      (await findEnd(END_OF_CENTRAL_DIRECTORY_BYTES)) ??
      (await findEnd(END_OF_CENTRAL_DIRECTORY_BYTES + MAX_ZIP_COMMENT_BYTES));
    if (!end) throw new Error('Invalid backup archive');
    const count = end.getUint16(10, true);
    const directoryBytes = end.getUint32(12, true);
    const directoryOffset = end.getUint32(16, true);
    if (count === MAX_ZIP32_ENTRIES || directoryOffset === MAX_ZIP32_BYTES)
      throw new Error('Backup archive uses ZIP64, which restore does not read');
    if (directoryOffset + directoryBytes > head.size) throw new Error('Invalid backup archive');

    const directory = await read(directoryOffset, directoryBytes);
    const decoder = new TextDecoder();
    const entries: Omit<ZipEntry, 'end'>[] = [];
    for (let at = 0, index = 0; index < count; index++) {
      if (
        at + CENTRAL_DIRECTORY_ENTRY_BYTES > directory.byteLength ||
        directory.getUint32(at, true) !== CENTRAL_DIRECTORY_SIGNATURE
      )
        throw new Error('Invalid backup archive');
      const nameBytes = directory.getUint16(at + 28, true);
      const skipped = directory.getUint16(at + 30, true) + directory.getUint16(at + 32, true);
      if (directory.getUint16(at + 8, true) & ENCRYPTED_FLAG) throw new Error('Backup archive entries are encrypted');
      entries.push({
        name: decoder.decode(
          new Uint8Array(directory.buffer, directory.byteOffset + at + CENTRAL_DIRECTORY_ENTRY_BYTES, nameBytes),
        ),
        method: directory.getUint16(at + 10, true),
        compressedSize: directory.getUint32(at + 20, true),
        size: directory.getUint32(at + 24, true),
        offset: directory.getUint32(at + 42, true),
      });
      at += CENTRAL_DIRECTORY_ENTRY_BYTES + nameBytes + skipped;
    }
    // Each entry's record runs to the next one's, or to the central directory.
    const byOffset = entries.toSorted((a, b) => a.offset - b.offset);
    return new R2ZipReader(
      bucket,
      key,
      head.size,
      byOffset.map((entry, index) => ({ ...entry, end: byOffset[index + 1]?.offset ?? directoryOffset })),
    );
  }

  // The entry's uncompressed bytes, from one range read of its record. Its local header, whose extra field may
  // differ from the central directory's, says where the data starts.
  async stream(entry: ZipEntry): Promise<ReadableStream<Uint8Array>> {
    if (entry.method !== STORED && entry.method !== DEFLATED)
      throw new Error(`Backup archive entry ${entry.name} uses an unsupported compression method`);
    const object = await this.bucket.get(this.key, {
      range: { offset: entry.offset, length: entry.end - entry.offset },
    });
    if (!object) throw new Error('Backup archive changed while it was read');
    const bytes = new ByteReader(object.body.getReader());
    const header = new DataView((await bytes.take(LOCAL_HEADER_BYTES)).slice().buffer);
    if (header.getUint32(0, true) !== LOCAL_HEADER_SIGNATURE) throw new Error('Invalid backup archive');
    await bytes.take(header.getUint16(26, true) + header.getUint16(28, true));
    const data = bytes.stream(entry.compressedSize);
    return entry.method === STORED ? data : data.pipeThrough(new DecompressionStream('deflate-raw'));
  }

  // A small entry's bytes; a larger one than maxBytes is refused before it is read.
  async bytes(entry: ZipEntry, maxBytes: number, tooLarge: string): Promise<Uint8Array> {
    if (entry.size > maxBytes) throw new Error(tooLarge);
    const bytes = new Uint8Array(await new Response(await this.stream(entry)).arrayBuffer());
    if (bytes.byteLength > maxBytes) throw new Error(tooLarge);
    return bytes;
  }
}
