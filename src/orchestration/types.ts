export type TaskStatus = "pending" | "ready" | "in_progress" | "done" | "blocked" | "failed";

export interface Task {
  id: string;
  goalId: string;
  domain: string;
  stepId: string; // WorkflowStep.id this task fulfills
  role: string; // sub-agent role that owns it, e.g. "sales", "finance"
  title: string;
  dependsOn: string[]; // task ids
  status: TaskStatus;
  input: Record<string, unknown>; // scoped context view handed to the sub-agent
  output?: Record<string, unknown>; // what the sub-agent wrote back
  assignedAgentId?: string;
  createdAt: string;
  updatedAt: string;
}
