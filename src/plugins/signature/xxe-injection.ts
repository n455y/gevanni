import {
  SignatureId,
} from "../../types/branded.ts";
import type { Evidence } from "../../types/models.ts";
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

export class XxeInjectionPlugin extends MutationFilteredSignaturePlugin {
  readonly name = SignatureId("xxe-injection");

  constructor(options?: { groups?: string[] }) {
    super([BuiltinMutationType.ReplaceValue], options);
  }

  protected async runAudit({ parameter, replay }: RunAuditContext) {
    const payload = BuiltinPayload.String(
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    );
    const instruction = parameter.createMutation(
      payload,
      BuiltinMutationType.ReplaceValue,
    );
    const result = await replay([instruction]);
    const allExchanges = result.allExchanges;
    const matches = allExchanges.filter((ex) =>
      XXE_ERROR_PATTERNS.some((p) => p.test(ex.response.body?.toString() ?? "")),
    );
    const evidence: Evidence = {
      judgmentId: "xxe-error-pattern",
      exchanges: allExchanges,
      evidenceExchanges: matches,
    };
    return {
      vulnerable: matches.length > 0,
      evidence,
      request: result.exchange.request,
      response: result.exchange.response,
    };
  }
}
