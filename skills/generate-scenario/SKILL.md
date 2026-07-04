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

### graphql (planned)
Generate gevanni scenarios for GraphQL APIs.

### grpc (planned)
Generate gevanni scenarios for gRPC services.

## Workflow

### Step 1: Parse arguments

1. Parse `$ARGUMENTS` to extract scenario type and source path:
   - If format is `<type>:<path>`, extract type and path
   - If format is just `<path>`, default type to `openapi`
2. Validate that the scenario type is supported
3. Validate that the source path exists

### Step 2: Select generator

Based on the scenario type, load the appropriate generator:

| Type      | Generator File                | Description                                  |
| --------- | ------------------------------ | -------------------------------------------- |
| `openapi` | `generators/openapi.md`       | OpenAPI 3.0 x-gevanni-scenarios generator    |
| `graphql` | `generators/graphql.md`       | GraphQL scenarios generator (planned)        |
| `grpc`    | `generators/grpc.md`          | gRPC scenarios generator (planned)           |

### Step 3: Execute generator

Delegate to the selected generator workflow:

1. Read the generator file corresponding to the scenario type
2. Follow the generator's workflow steps
3. Apply the generator's validation rules

### Step 4: Output results

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
