import { BroadcastCommand } from "../core/command.js";
import type { InspectionParameter } from "../types/models.js";
import type { InspectorDefinition } from "../core/inspector.js";

class CreateInspectorsCommand extends BroadcastCommand<InspectorDefinition[]> {
  readonly type = "createInspectors";
  constructor(readonly parameters: InspectionParameter[]) {
    super();
  }
}
export { CreateInspectorsCommand };
