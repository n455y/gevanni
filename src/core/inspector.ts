import { InspectionParameter } from "../types/models.js";

interface InspectorDefinition {
  readonly signatureName: string;
  readonly parameter: InspectionParameter;
}

export { InspectorDefinition };
