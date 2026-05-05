import type { PluginRegistry } from "./core/plugin.js";
import { PostmanPlugin } from "./plugins/scenario/postman.js";
import { HttpProxyPlugin } from "./plugins/proxy/http-proxy.js";
import { QueryParserPlugin } from "./plugins/parser/query-parser.js";
import { JsonParserPlugin } from "./plugins/parser/json-parser.js";
import { FormParserPlugin } from "./plugins/parser/form-parser.js";
import { QueryTamperPlugin } from "./plugins/tamper/query-tamper.js";
import { JsonTamperPlugin } from "./plugins/tamper/json-tamper.js";
import { FormTamperPlugin } from "./plugins/tamper/form-tamper.js";
import { ReflectedXssPlugin } from "./plugins/signature/reflected-xss.js";
import { SqliErrorPlugin } from "./plugins/signature/sqli-error.js";
import { JsonStoragePlugin } from "./plugins/storage/json-storage.js";
import { ConsoleReporterPlugin } from "./plugins/reporter/console-reporter.js";
import { JsonReporterPlugin } from "./plugins/reporter/json-reporter.js";

function registerBuiltinPlugins(registry: PluginRegistry): void {
  registry.register("scenarioReplayer", "postman", () => new PostmanPlugin());
  registry.register("proxy", "http-proxy", () => new HttpProxyPlugin());
  registry.register("parser", "query-parser", () => new QueryParserPlugin());
  registry.register("parser", "json-parser", () => new JsonParserPlugin());
  registry.register("parser", "form-parser", () => new FormParserPlugin());
  registry.register("tamper", "query-tamper", () => new QueryTamperPlugin());
  registry.register("tamper", "json-tamper", () => new JsonTamperPlugin());
  registry.register("tamper", "form-tamper", () => new FormTamperPlugin());
  registry.register("signature", "reflected-xss", () => new ReflectedXssPlugin());
  registry.register("signature", "sqli-error", () => new SqliErrorPlugin());
  registry.register("storage", "json-storage", () => new JsonStoragePlugin());
  registry.register("reporter", "console-reporter", () => new ConsoleReporterPlugin());
  registry.register("reporter", "json-reporter", () => new JsonReporterPlugin());
}

export { registerBuiltinPlugins };
