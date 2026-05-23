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

type PluginFactory = (options: Record<string, unknown>) => Plugin;

const builtinPlugins: PluginFactory[] = [
  () => new PostmanPlugin(),
  () => new OpenApiPlugin(),
  (opts) => new HttpProxyPlugin(opts as HttpProxyConfig),
  () => new QueryParserPlugin(),
  () => new JsonParserPlugin(),
  () => new FormParserPlugin(),
  () => new HeaderParserPlugin(),
  () => new CookieParserPlugin(),
  () => new GraphQLParserPlugin(),
  () => new QueryMutationPlugin(),
  () => new JsonMutationPlugin(),
  () => new FormMutationPlugin(),
  () => new HeaderMutationPlugin(),
  () => new CookieMutationPlugin(),
  () => new GraphQLMutationPlugin(),
  () => new ReflectedXssPlugin(),
  () => new SqliErrorPlugin(),
  (opts) => new JsonStoragePlugin(opts as JsonStorageConfig),
  () => new ConsoleReporterPlugin(),
  (opts) => new JsonReporterPlugin(opts as JsonReporterConfig),
];

export const builtinPluginFactories = new Map<string, PluginFactory>(
  builtinPlugins.map((factory) => [factory({} as Record<string, unknown>).name, factory]),
);
