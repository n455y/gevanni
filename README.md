# gevanni

CLI-based web application vulnerability scanner.

## Requirements

- Node.js >= 24.12.0（ネイティブ TypeScript 実行のため。type stripping が stable なバージョンが必要です）

## Install

```bash
npm install -g gevanni
```

## Usage

```bash
gevanni scan -s openapi:./spec.yaml
```

開発時はビルド不要で直接実行できます:

```bash
npm run gevanni -- scan -s openapi:./spec.yaml
```

ライブラリとしても利用可能です（Node 24.12+ 必需）:

```ts
import { builtinPluginFactories } from "gevanni";
```

## Claude Code Plugin

gevanni is also available as a Claude Code plugin for security scanning directly within your development environment.

### Plugin Installation

Install the plugin from GitHub:

```bash
claude plugin install github.com/username/gevanni
```

Replace `username` with your GitHub username or organization.

### Plugin Usage

Once installed, you can use the following slash commands:

```bash
/gevanni:dast [target]
```
Run Dynamic Application Security Testing against a target URL or application.

```bash
/gevanni:sast [source]
```
Run Static Application Security Testing against source code.

```bash
/gevanni:generate-scenario [type]:[path]
```
Generate test scenarios from various API specifications (OpenAPI, GraphQL, gRPC).

### Available Skills

- **dast** - Dynamic application security testing
- **sast** - Static application security testing
- **generate-scenario** - Scenario generation for various API types (OpenAPI, GraphQL, gRPC)
