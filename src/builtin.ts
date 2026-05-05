import type { PluginRegistry } from "./core/plugin.js";
import { createPostmanPlugin } from "./plugins/scenario/postman.js";
import { createHttpProxyPlugin } from "./plugins/proxy/http-proxy.js";
import { createQueryParserPlugin } from "./plugins/parser/query-parser.js";
import { createJsonParserPlugin } from "./plugins/parser/json-parser.js";
import { createFormParserPlugin } from "./plugins/parser/form-parser.js";
import { createQueryTamperPlugin } from "./plugins/tamper/query-tamper.js";
import { createJsonTamperPlugin } from "./plugins/tamper/json-tamper.js";
import { createFormTamperPlugin } from "./plugins/tamper/form-tamper.js";
import { createReflectedXssPlugin } from "./plugins/signature/reflected-xss.js";
import { createSqliErrorPlugin } from "./plugins/signature/sqli-error.js";
import { createJsonStoragePlugin } from "./plugins/storage/json-storage.js";
import { createConsoleReporterPlugin } from "./plugins/reporter/console-reporter.js";
import { createJsonReporterPlugin } from "./plugins/reporter/json-reporter.js";

function registerBuiltinPlugins(registry: PluginRegistry): void {
  registry.register("scenarioReplayer", "postman", createPostmanPlugin);
  registry.register("proxy", "http-proxy", createHttpProxyPlugin);
  registry.register("parser", "query-parser", createQueryParserPlugin);
  registry.register("parser", "json-parser", createJsonParserPlugin);
  registry.register("parser", "form-parser", createFormParserPlugin);
  registry.register("tamper", "query-tamper", createQueryTamperPlugin);
  registry.register("tamper", "json-tamper", createJsonTamperPlugin);
  registry.register("tamper", "form-tamper", createFormTamperPlugin);
  registry.register("signature", "reflected-xss", createReflectedXssPlugin);
  registry.register("signature", "sqli-error", createSqliErrorPlugin);
  registry.register("storage", "json-storage", createJsonStoragePlugin);
  registry.register("reporter", "console-reporter", createConsoleReporterPlugin);
  registry.register("reporter", "json-reporter", createJsonReporterPlugin);
}

export { registerBuiltinPlugins };
