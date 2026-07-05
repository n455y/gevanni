---
name: generate-scenario
description: Generate gevanni-compatible scenario definitions for various API specification formats. Use this skill when the user wants to create or update API spec files with vulnerability scanning scenarios for the gevanni scanner, or when they ask to generate test scenarios from their API source code.
---

# Generate Gevanni Scenarios

Generate gevanni-compatible scenario definitions for various API specification formats.

## Arguments

- `$ARGUMENTS`: Scenario type followed by path to source:
  - Format: `<type>:<path>` or `<path>` (defaults to `openapi`)
  - Supported types: `openapi`, `graphql` (planned), `grpc` (planned)
  - Examples: `openapi:./src`, `:./src` (defaults to openapi), `./src`

## Supported Scenario Types

### openapi

Generate `x-gevanni-scenarios` for OpenAPI 3.0 specs. Analyzes web application source code and creates gevanni-compatible scenario definitions.

## Workflow

### Step 1: Gather required runtime parameters

Before generating scenarios, identify parameters that cannot be extracted from the code:

**A. Confirm target server base URL:**

- The base URL of the web server to scan (e.g., `http://localhost:3000`, `https://api.example.com`)
- This is used in the OpenAPI spec's `servers` field
- If the codebase has configuration files (`.env`, `config.js`, `application.yml`, etc.), check them for hints, but always confirm with the user

**B. Identify required credentials:**

- Login credentials (username/email, password)
- API keys or tokens
- Multi-factor authentication codes (TOTP seeds, backup codes)
- Any authentication data needed to access protected endpoints

**C. Identify required dynamic test data:**

- Discount/coupon codes
- Invitation codes
- Test account identifiers
- Any application-specific codes needed for testing

**D. Confirmation workflow:**
For each required parameter discovered:

1. **Ask the user** for the actual value
2. **Do not invent or guess** values like `http://localhost:3000`, `test@example.com`, `password123`, or `DISCOUNT20`
3. Store the provided values in the appropriate scenario examples

**Exception - OpenAPI Links:**
Parameters that can be extracted from previous step responses (via `$response.body#/...`, `$response.header#/...`) should **NOT** be asked — define these in the OpenAPI spec using Links. For example:

- User ID returned by a `createUser` operation → use in `getUserById` path parameter
- Order ID returned by `createOrder` → use in `trackOrder` query parameter
- Token returned by `login` → use in `Authorization` header via `securitySchemes.x-gevanni-token`

### Step 2: Parse arguments

1. Parse `$ARGUMENTS` to extract scenario type and source path:
   - If format is `<type>:<path>`, extract type and path
   - If format is just `<path>`, default type to `openapi`
2. Validate that the scenario type is supported
3. Validate that the source path exists

### Step 3: Select generator

Based on the scenario type, load the appropriate generator:

| Type      | Generator File          | Description                               |
| --------- | ----------------------- | ----------------------------------------- |
| `openapi` | `generators/openapi.md` | OpenAPI 3.0 x-gevanni-scenarios generator |
| `graphql` | `generators/graphql.md` | GraphQL scenarios generator (planned)     |
| `grpc`    | `generators/grpc.md`    | gRPC scenarios generator (planned)        |

### Step 4: Execute generator

Delegate to the selected generator workflow:

1. Read the generator file corresponding to the scenario type
2. Follow the generator's workflow steps
3. Apply the generator's validation rules

### Step 5: Output results

The selected generator will produce:

- Generated scenario definitions
- Validation reports
- Coverage analysis
- Warnings and recommendations

## Output Location

Generated scenario files are saved relative to the directory where the skill is invoked:

```
<project-root>/
  .gevanni/
    scenarios/
      openapi.yaml          # OpenAPI spec with x-gevanni-scenarios
```

- **Output location**: `.gevanni/scenarios/openapi.yaml`
- **Auto-creation**: The `.gevanni/scenarios/` directory is created automatically if it doesn't exist

### .gitignore Recommendation

Add `.gevanni/` to your `.gitignore` to prevent committing generated files:

```gitignore
# Gevanni generated scenarios
.gevanni/
```

Generated scenarios are project-specific and should be regenerated from source code rather than tracked in version control.

## Error Handling

If the scenario type is not supported:

```
Error: Unsupported scenario type '<type>'. Supported types: openapi
```

If the generator file is missing:

```
Error: Generator file not found for type '<type>': generators/<type>.md
```

## Extension Guide

To add a new scenario type:

1. Create a new generator file: `generators/<type>.md`
2. Add the type to the supported types list above
3. Implement the generator workflow following the established pattern
4. Update this file to include the new type in the selection table

## Examples

```bash
# Generate OpenAPI scenarios from current directory
/generate-scenario :.

# Generate OpenAPI scenarios from specific path
/generate-scenario openapi:./src

# Future: Generate GraphQL scenarios
/generate-scenario graphql:./graphql-schema
```

## Related Skills

- **gevanni-run-model**: Execute gevanni scanner with generated scenarios
- **sast**: Static application security testing perspectives
