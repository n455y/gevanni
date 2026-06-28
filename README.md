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
