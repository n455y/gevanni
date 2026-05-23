import type { Plugin } from "./core/plugin.ts";
import { PostmanPlugin } from "./plugins/scenario/postman.ts";
import { OpenApiPlugin } from "./plugins/scenario/openapi.ts";
import { HttpProxyPlugin, type HttpProxyConfig } from "./plugins/proxy/http-proxy.ts";
import { QueryParserPlugin, QueryMutationPlugin } from "./plugins/parameter/query.ts";
import { JsonParserPlugin, JsonMutationPlugin } from "./plugins/parameter/json.ts";
import { FormParserPlugin, FormMutationPlugin } from "./plugins/parameter/form.ts";
import { HeaderParserPlugin, HeaderMutationPlugin } from "./plugins/parameter/header.ts";
import { CookieParserPlugin, CookieMutationPlugin } from "./plugins/parameter/cookie.ts";
import { ReflectedXssPlugin } from "./plugins/signature/reflected-xss.ts";
import { SqliErrorPlugin } from "./plugins/signature/sqli-error.ts";
import { JsonStoragePlugin, type JsonStorageConfig } from "./plugins/storage/json-storage.ts";
import { ConsoleReporterPlugin } from "./plugins/reporter/console-reporter.ts";
import { JsonReporterPlugin, type JsonReporterConfig } from "./plugins/reporter/json-reporter.ts";
import { GraphQLParserPlugin, GraphQLMutationPlugin } from "./plugins/parameter/graphql.ts";

export const builtinPluginFactories = new Map<
  string,
  (options: Record<string, unknown>) => Plugin
>([
  ["scenarioReplayer:postman", () => new PostmanPlugin()],
  ["scenarioReplayer:openapi", () => new OpenApiPlugin()],
  ["proxy:http-proxy", (opts) => new HttpProxyPlugin(opts as HttpProxyConfig)],
  ["parser:query-parser", () => new QueryParserPlugin()],
  ["parser:json-parser", () => new JsonParserPlugin()],
  ["parser:form-parser", () => new FormParserPlugin()],
  ["parser:header-parser", () => new HeaderParserPlugin()],
  ["parser:cookie-parser", () => new CookieParserPlugin()],
  ["parser:graphql-parser", () => new GraphQLParserPlugin()],
  ["mutation:query-mutation", () => new QueryMutationPlugin()],
  ["mutation:json-mutation", () => new JsonMutationPlugin()],
  ["mutation:form-mutation", () => new FormMutationPlugin()],
  ["mutation:header-mutation", () => new HeaderMutationPlugin()],
  ["mutation:cookie-mutation", () => new CookieMutationPlugin()],
  ["mutation:graphql-mutation", () => new GraphQLMutationPlugin()],
  ["signature:reflected-xss", () => new ReflectedXssPlugin()],
  ["signature:sqli-error", () => new SqliErrorPlugin()],
  ["storage:json-storage", (opts) => new JsonStoragePlugin(opts as JsonStorageConfig)],
  ["reporter:console-reporter", () => new ConsoleReporterPlugin()],
  ["reporter:json-reporter", (opts) => new JsonReporterPlugin(opts as JsonReporterConfig)],
]);
