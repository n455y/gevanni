declare module "newman" {
  import type { Agent as HttpAgent } from "node:http";
  import type { Agent as HttpsAgent } from "node:https";

  interface NewmanRunOptions {
    collection: Record<string, unknown>;
    reporters?: string[];
    environment?: Record<string, unknown>;
    globals?: Record<string, unknown>;
    iterationData?: unknown;
    folder?: string | string[];
    timeout?: number;
    timeoutRequest?: number;
    timeoutScript?: number;
    delayRequest?: number;
    ignoreRedirects?: boolean;
    insecure?: boolean;
    bail?: boolean | string[];
    requestAgents?: {
      http?: HttpAgent;
      https?: HttpsAgent;
    };
    suppressExitCode?: boolean;
  }

  interface NewmanHeader {
    key: string;
    value: string;
  }

  interface NewmanHeaderList {
    members: NewmanHeader[];
    reference: unknown;
    Type: unknown;
    _postman_listIndexKey: string;
    _postman_listIndexCaseInsensitive: boolean;
    _postman_listAllowsMultipleValues: boolean;
  }

  interface NewmanResponse {
    id: string;
    status: string;
    code: number;
    headers: NewmanHeaderList;
    stream: Buffer;
    cookies: unknown[];
    responseTime: number;
    responseSize: number;
  }

  interface NewmanExecution {
    cursor: unknown;
    item: unknown;
    request: unknown;
    response: NewmanResponse | undefined;
    id: string;
    requestError: Error | undefined;
  }

  interface NewmanRunSummary {
    run: {
      executions: NewmanExecution[];
      stats: {
        iterations: { total: number; pending: number; failed: number };
        items: { total: number; pending: number; failed: number };
        scripts: { total: number; pending: number; failed: number };
        prerequests: { total: number; pending: number; failed: number };
        requests: { total: number; pending: number; failed: number };
        tests: { total: number; pending: number; failed: number };
        assertions: { total: number; pending: number; failed: number };
        testScripts: { total: number; pending: number; failed: number };
        prerequestScripts: { total: number; pending: number; failed: number };
      };
    };
  }

  function run(
    options: NewmanRunOptions,
    callback?: (err: Error | null, summary: NewmanRunSummary) => void,
  ): { on: (event: string, callback: (...args: unknown[]) => void) => void };

  export { run };
  export default { run };
}
