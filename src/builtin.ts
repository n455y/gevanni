import type { PluginRegistry } from "./core/plugin.ts";
import { PostmanPlugin } from "./plugins/scenario/postman.ts";
import { OpenApiPlugin } from "./plugins/scenario/openapi.ts";
import { HttpProxyPlugin } from "./plugins/proxy/http-proxy.ts";
import { QueryParserPlugin, QueryMutationPlugin } from "./plugins/parameter/query.ts";
import { JsonParserPlugin, JsonMutationPlugin } from "./plugins/parameter/json.ts";
import { FormParserPlugin, FormMutationPlugin } from "./plugins/parameter/form.ts";
import { HeaderParserPlugin, HeaderMutationPlugin } from "./plugins/parameter/header.ts";
import { CookieParserPlugin, CookieMutationPlugin } from "./plugins/parameter/cookie.ts";
import { ReflectedXssPlugin } from "./plugins/signature/reflected-xss.ts";
import { SqliErrorPlugin } from "./plugins/signature/sqli-error.ts";
import { JsonStoragePlugin } from "./plugins/storage/json-storage.ts";
import { ConsoleReporterPlugin } from "./plugins/reporter/console-reporter.ts";
import { JsonReporterPlugin } from "./plugins/reporter/json-reporter.ts";
import { GraphQLParserPlugin, GraphQLMutationPlugin } from "./plugins/parameter/graphql.ts";

export function registerBuiltinPlugins(registry: PluginRegistry): void {
  registry.register("scenarioReplayer", "postman", () => new PostmanPlugin());
  registry.register("scenarioReplayer", "openapi", () => new OpenApiPlugin());
  registry.register("proxy", "http-proxy", () => new HttpProxyPlugin());
  registry.register("parser", "query-parser", () => new QueryParserPlugin());
  registry.register("parser", "json-parser", () => new JsonParserPlugin());
  registry.register("parser", "form-parser", () => new FormParserPlugin());
  registry.register("parser", "header-parser", () => new HeaderParserPlugin());
  registry.register("parser", "cookie-parser", () => new CookieParserPlugin());
  registry.register("parser", "graphql-parser", () => new GraphQLParserPlugin());
  registry.register("mutation", "query-mutation", () => new QueryMutationPlugin());
  registry.register("mutation", "json-mutation", () => new JsonMutationPlugin());
  registry.register("mutation", "form-mutation", () => new FormMutationPlugin());
  registry.register("mutation", "header-mutation", () => new HeaderMutationPlugin());
  registry.register("mutation", "cookie-mutation", () => new CookieMutationPlugin());
  registry.register("mutation", "graphql-mutation", () => new GraphQLMutationPlugin());
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
