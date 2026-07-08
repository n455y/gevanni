import type { Plugin, PluginRegistry } from "./core/plugin.ts";
import OpenApiPlugin from "./plugins/scenario/openapi/plugin.ts";
import OpenApiLoaderPlugin from "./plugins/scenario/openapi/loader.ts";
import HttpProxyPlugin, { type HttpProxyConfig } from "./plugins/proxy/http-proxy.ts";
import QueryParserPlugin from "./plugins/parameter/query/parser.ts";
import QueryMutationPlugin from "./plugins/parameter/query/mutation.ts";
import JsonParserPlugin from "./plugins/parameter/json/parser.ts";
import JsonMutationPlugin from "./plugins/parameter/json/mutation.ts";
import FormParserPlugin from "./plugins/parameter/form/parser.ts";
import FormMutationPlugin from "./plugins/parameter/form/mutation.ts";
import HeaderParserPlugin from "./plugins/parameter/header/parser.ts";
import HeaderMutationPlugin from "./plugins/parameter/header/mutation.ts";
import CookieParserPlugin from "./plugins/parameter/cookie/parser.ts";
import CookieMutationPlugin from "./plugins/parameter/cookie/mutation.ts";
import PathParserPlugin from "./plugins/parameter/path/parser.ts";
import PathMutationPlugin from "./plugins/parameter/path/mutation.ts";
import GraphQLParserPlugin from "./plugins/parameter/graphql/parser.ts";
import GraphQLMutationPlugin from "./plugins/parameter/graphql/mutation.ts";
import ReflectedXssPlugin from "./plugins/signature/reflected-xss.ts";
import SqliErrorPlugin from "./plugins/signature/sqli-error.ts";
import SqliBooleanPlugin from "./plugins/signature/sqli-boolean.ts";
import SqliDiffPlugin from "./plugins/signature/sqli-diff.ts";
import ExactDiffPlugin from "./plugins/diff/exact.ts";
import JsonDiffPlugin from "./plugins/diff/json.ts";
import HtmlDiffPlugin from "./plugins/diff/html.ts";
import SqliTimePlugin from "./plugins/signature/sqli-time.ts";
import SqliUnionPlugin from "./plugins/signature/sqli-union.ts";
import LdapInjectionPlugin from "./plugins/signature/ldap-injection.ts";
import OsCommandInjectionPlugin from "./plugins/signature/os-command-injection.ts";
import PathTraversalPlugin from "./plugins/signature/path-traversal.ts";
import SstiPlugin from "./plugins/signature/ssti.ts";
import XpathInjectionPlugin from "./plugins/signature/xpath-injection.ts";
import NosqlInjectionPlugin from "./plugins/signature/nosql-injection.ts";
import XxeInjectionPlugin from "./plugins/signature/xxe-injection.ts";
import CrlfInjectionPlugin from "./plugins/signature/crlf-injection.ts";
import SsiInjectionPlugin from "./plugins/signature/ssi-injection.ts";
import PrototypePollutionPlugin from "./plugins/signature/prototype-pollution.ts";
import SsrfPlugin from "./plugins/signature/ssrf.ts";
import type { SsrfPluginOptions } from "./plugins/signature/ssrf.ts";
import InfoDisclosurePlugin from "./plugins/signature/info-disclosure.ts";
import type { InfoDisclosurePluginOptions } from "./plugins/signature/info-disclosure.ts";
import ZipSlipPlugin from "./plugins/signature/zip-slip.ts";
import type { ZipSlipPluginOptions } from "./plugins/signature/zip-slip.ts";
import HppPlugin from "./plugins/signature/hpp.ts";
import type { HppPluginOptions } from "./plugins/signature/hpp.ts";
import JsonStoragePlugin, { type JsonStorageConfig } from "./plugins/storage/json-storage.ts";
import ConsoleReporterPlugin from "./plugins/reporter/console-reporter.ts";
import JsonReporterPlugin, { type JsonReporterConfig } from "./plugins/reporter/json-reporter.ts";
import NosqlBooleanPlugin from "./plugins/signature/nosql-boolean.ts";
import NosqlDiffPlugin from "./plugins/signature/nosql-diff.ts";

type PluginFactory = (options: Record<string, unknown>) => Plugin;

const builtinPlugins: PluginFactory[] = [
  () => new OpenApiPlugin(),
  () => new OpenApiLoaderPlugin(),
  (opts) => new HttpProxyPlugin(opts as HttpProxyConfig),
  () => new QueryParserPlugin(),
  () => new PathParserPlugin(),
  () => new JsonParserPlugin(),
  () => new FormParserPlugin(),
  () => new HeaderParserPlugin(),
  () => new CookieParserPlugin(),
  () => new GraphQLParserPlugin(),
  () => new QueryMutationPlugin(),
  () => new PathMutationPlugin(),
  () => new JsonMutationPlugin(),
  () => new FormMutationPlugin(),
  () => new HeaderMutationPlugin(),
  () => new CookieMutationPlugin(),
  () => new GraphQLMutationPlugin(),
  () => new ReflectedXssPlugin(),
  () => new SqliErrorPlugin(),
  () => new SqliBooleanPlugin(),
  () => new SqliDiffPlugin(),
  () => new JsonDiffPlugin(),
  () => new HtmlDiffPlugin(),
  () => new ExactDiffPlugin(),
  () => new SqliTimePlugin(),
  () => new SqliUnionPlugin(),
  () => new LdapInjectionPlugin(),
  () => new OsCommandInjectionPlugin(),
  () => new PathTraversalPlugin(),
  () => new SstiPlugin(),
  () => new XpathInjectionPlugin(),
  () => new NosqlInjectionPlugin(),
  () => new NosqlBooleanPlugin(),
  () => new NosqlDiffPlugin(),
  () => new XxeInjectionPlugin(),
  () => new CrlfInjectionPlugin(),
  () => new SsiInjectionPlugin(),
  () => new PrototypePollutionPlugin(),
  (opts) => new SsrfPlugin(opts as SsrfPluginOptions),
  (opts) => new InfoDisclosurePlugin(opts as InfoDisclosurePluginOptions),
  (opts) => new ZipSlipPlugin(opts as ZipSlipPluginOptions),
  (opts) => new HppPlugin(opts as HppPluginOptions),
  (opts) => new JsonStoragePlugin(opts as JsonStorageConfig),
  () => new ConsoleReporterPlugin(),
  (opts) => new JsonReporterPlugin(opts as JsonReporterConfig),
];

export const builtinPluginFactories = new Map<string, PluginFactory>(
  builtinPlugins.map((factory) => [factory({} as Record<string, unknown>).name, factory]),
);

export function registerAllBuiltinPlugins(
  registry: PluginRegistry,
  overrides?: Record<string, Record<string, unknown>>,
): void {
  for (const [name, factory] of builtinPluginFactories) {
    registry.register(factory(overrides?.[name] ?? ({} as Record<string, unknown>)));
  }
}

/**
 * Register a single builtin plugin (for overriding options).
 * If a plugin with the same name is already registered, it is overwritten (last wins).
 */
export function registerBuiltinPlugin(
  registry: PluginRegistry,
  name: string,
  options: Record<string, unknown>,
): void {
  const factory = builtinPluginFactories.get(name);
  if (!factory) {
    throw new Error(`Unknown builtin plugin: ${name}`);
  }
  registry.register(factory(options));
}
