/**
 * Generic HTTP request sender — no dependency on OpenAPI, scenarios, or any plugin.
 *
 * Extracted from validate-scenarios.ts so it can be reused by any scenario plugin
 * that needs to send validation HTTP requests.
 */

import http from "node:http";
import https from "node:https";
import { HttpProxyAgent } from "http-proxy-agent";
import { HttpsProxyAgent } from "https-proxy-agent";

export interface SimpleResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: Buffer | null;
}

const DEFAULT_TIMEOUT_MS = 15_000;

export function sendHttpRequest(
  method: string,
  url: string,
  headers: Record<string, string>,
  body: string | null,
  upstreamProxyUrl?: string,
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<SimpleResponse> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const isHttps = parsed.protocol === "https:";

    const agent = upstreamProxyUrl
      ? isHttps
        ? new HttpsProxyAgent(upstreamProxyUrl)
        : new HttpProxyAgent(upstreamProxyUrl)
      : undefined;

    const options: https.RequestOptions = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method,
      headers,
      rejectUnauthorized: false,
      timeout: timeoutMs,
      ...(agent ? { agent } : {}),
    };

    const req = (isHttps ? https : http).request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => {
        const resHeaders: Record<string, string> = {};
        for (const [key, value] of Object.entries(res.headers)) {
          if (typeof value === "string") resHeaders[key] = value;
          else if (Array.isArray(value)) resHeaders[key] = value.join(", ");
        }
        resolve({
          statusCode: res.statusCode ?? 0,
          headers: resHeaders,
          body: chunks.length > 0 ? Buffer.concat(chunks) : null,
        });
      });
      res.on("error", reject);
    });

    req.on("timeout", () => {
      req.destroy();
      reject(new Error(`HTTP timeout after ${timeoutMs}ms`));
    });
    req.on("error", reject);

    if (body) req.write(body);
    req.end();
  });
}
