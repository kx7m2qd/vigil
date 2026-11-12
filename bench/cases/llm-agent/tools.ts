import Anthropic from "@anthropic-ai/sdk";
import { exec } from "node:child_process";
import { promisify } from "node:util";
import { z } from "zod";

const run = promisify(exec);
const client = new Anthropic();

export async function shellTool(goal: string) {
  const reply = await client.messages.create({
    model: "claude-haiku-5-5",
    max_tokens: 512,
    messages: [{ role: "user", content: `Give one bash command to ${goal}. Reply with the command only.` }],
  });
  const block = reply.content.find((b) => b.type === "text");
  const command = block && block.type === "text" ? block.text.trim() : "true";
  // expect: js-llm-output-to-dangerous-sink
  const { stdout } = await run(command);
  return stdout;
}

const Step = z.object({ tool: z.enum(["git_status", "list_files"]) });
const COMMANDS = { git_status: "git status --short", list_files: "ls -la" } as const;

// Safe: the model picks from an allow-list; the command text never comes from the model.
export async function shellToolSafe(goal: string) {
  const reply = await client.messages.create({
    model: "claude-haiku-5-5",
    max_tokens: 128,
    messages: [{ role: "user", content: `Pick a tool for: ${goal}. JSON only.` }],
  });
  const block = reply.content.find((b) => b.type === "text");
  const step = Step.parse(JSON.parse(block && block.type === "text" ? block.text : "{}"));
  const { stdout } = await run(COMMANDS[step.tool]);
  return stdout;
}
