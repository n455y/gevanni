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
import { SqliBooleanPlugin } from "./plugins/signature/sqli-boolean.ts";
import { SqliTimePlugin } from "./plugins/signature/sqli-time.ts";
import { SqliUnionPlugin } from "./plugins/signature/sqli-union.ts";
import { LdapInjectionPlugin } from "./plugins/signature/ldap-injection.ts";
import { OsCommandInjectionPlugin } from "./plugins/signature/os-command-injection.ts";
import { PathTraversalPlugin } from "./plugins/signature/path-traversal.ts";
import { SstiPlugin } from "./plugins/signature/ssti.ts";
import { XpathInjectionPlugin } from "./plugins/signature/xpath-injection.ts";
import { NosqlInjectionPlugin } from "./plugins/signature/nosql-injection.ts";
import { XxeInjectionPlugin } from "./plugins/signature/xxe-injection.ts";
import { CrlfInjectionPlugin } from "./plugins/signature/crlf-injection.ts";
import { SsiInjectionPlugin } from "./plugins/signature/ssi-injection.ts";
import { PrototypePollutionPlugin } from "./plugins/signature/prototype-pollution.ts";
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
  (opts) => new ReflectedXssPlugin(opts as { groups?: string[] }),
  (opts) => new SqliErrorPlugin(opts as { groups?: string[] }),
  (opts) => new SqliBooleanPlugin(opts as { groups?: string[] }),
  (opts) => new SqliTimePlugin(opts as { groups?: string[] }),
  (opts) => new SqliUnionPlugin(opts as { groups?: string[] }),
  (opts) => new LdapInjectionPlugin(opts as { groups?: string[] }),
  (opts) => new OsCommandInjectionPlugin(opts as { groups?: string[] }),
  (opts) => new PathTraversalPlugin(opts as { groups?: string[] }),
  (opts) => new SstiPlugin(opts as { groups?: string[] }),
  (opts) => new XpathInjectionPlugin(opts as { groups?: string[] }),
  (opts) => new NosqlInjectionPlugin(opts as { groups?: string[] }),
  (opts) => new XxeInjectionPlugin(opts as { groups?: string[] }),
  (opts) => new CrlfInjectionPlugin(opts as { groups?: string[] }),
  (opts) => new SsiInjectionPlugin(opts as { groups?: string[] }),
  (opts) => new PrototypePollutionPlugin(opts as { groups?: string[] }),
  (opts) => new JsonStoragePlugin(opts as JsonStorageConfig),
  () => new ConsoleReporterPlugin(),
  (opts) => new JsonReporterPlugin(opts as JsonReporterConfig),
];

export const builtinPluginFactories = new Map<string, PluginFactory>(
  builtinPlugins.map((factory) => [factory({} as Record<string, unknown>).name, factory]),
);
