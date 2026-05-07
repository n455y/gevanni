import type { PluginRegistry } from "./core/plugin.js";
import { PostmanPlugin } from "./plugins/scenario/postman.js";
import { PostmanLoaderPlugin } from "./plugins/loader/postman-loader.js";
import { HttpProxyPlugin } from "./plugins/proxy/http-proxy.js";
import { QueryParserPlugin, QueryTamperPlugin } from "./plugins/parameter/query.js";
import { JsonParserPlugin, JsonTamperPlugin } from "./plugins/parameter/json.js";
import { FormParserPlugin, FormTamperPlugin } from "./plugins/parameter/form.js";
import { HeaderParserPlugin, HeaderTamperPlugin } from "./plugins/parameter/header.js";
import { ReflectedXssPlugin } from "./plugins/signature/reflected-xss.js";
import { SqliErrorPlugin } from "./plugins/signature/sqli-error.js";
import { JsonStoragePlugin } from "./plugins/storage/json-storage.js";
import { ConsoleReporterPlugin } from "./plugins/reporter/console-reporter.js";
import { JsonReporterPlugin } from "./plugins/reporter/json-reporter.js";
import { GraphQLParserPlugin, GraphQLTamperPlugin } from "./plugins/parameter/graphql.js";

function registerBuiltinPlugins(registry: PluginRegistry): void {
  registry.register("scenarioReplayer", "postman", () => new PostmanPlugin());
  registry.register(
    "scenarioLoader",
    "postman",
    () => new PostmanLoaderPlugin(),
  );
  registry.register("proxy", "http-proxy", () => new HttpProxyPlugin());
  registry.register("parser", "query-parser", () => new QueryParserPlugin());
  registry.register("parser", "json-parser", () => new JsonParserPlugin());
  registry.register("parser", "form-parser", () => new FormParserPlugin());
  registry.register("parser", "header-parser", () => new HeaderParserPlugin());
  registry.register("parser", "graphql-parser", () => new GraphQLParserPlugin());
  registry.register("tamper", "query-tamper", () => new QueryTamperPlugin());
  registry.register("tamper", "json-tamper", () => new JsonTamperPlugin());
  registry.register("tamper", "form-tamper", () => new FormTamperPlugin());
  registry.register("tamper", "header-tamper", () => new HeaderTamperPlugin());
  registry.register("tamper", "graphql-tamper", () => new GraphQLTamperPlugin());
  registry.register(
    "signature",
    "reflected-xss",
    () => new ReflectedXssPlugin(),
  );
  registry.register("signature", "sqli-error", () => new SqliErrorPlugin());
  registry.register("storage", "json-storage", () => new JsonStoragePlugin());
  registry.register(
    "reporter",
    "console-reporter",
    () => new ConsoleReporterPlugin(),
  );
  registry.register(
    "reporter",
    "json-reporter",
    () => new JsonReporterPlugin(),
  );
}

export { registerBuiltinPlugins };
