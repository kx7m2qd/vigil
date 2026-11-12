import Anthropic from '@anthropic-ai/sdk';
import OpenAI from 'openai';
import { exec, execSync } from 'node:child_process';
import { promisify } from 'node:util';
import { z } from 'zod';

const anthropic = new Anthropic();
const openai = new OpenAI();
const run = promisify(exec);

export async function runAgentStep(task: string) {
  const msg = await anthropic.messages.create({
    model: 'claude-haiku-5-5',
    max_tokens: 1024,
    messages: [{ role: 'user', content: `Write a shell command to: ${task}` }],
  });
  const cmd = msg.content[0].type === 'text' ? msg.content[0].text : '';
  // ruleid: js-llm-output-to-dangerous-sink
  return execSync(cmd).toString();
}

export async function calculator(question: string) {
  const r = await openai.chat.completions.create({
    model: 'gpt-4.1-mini',
    messages: [{ role: 'user', content: `Reply with a JS expression for: ${question}` }],
  });
  // ruleid: js-llm-output-to-dangerous-sink
  return eval(r.choices[0].message.content ?? '0');
}

export async function textToSql(question: string) {
  const r = await openai.responses.create({ model: 'gpt-4.1-mini', input: `SQL for: ${question}` });
  const sql = r.output_text;
  // ruleid: js-llm-output-to-dangerous-sink
  return pool.query(sql);
}

const Action = z.object({ action: z.enum(['list', 'status']) });

export async function runAgentSafe(task: string) {
  const msg = await anthropic.messages.create({
    model: 'claude-haiku-5-5',
    max_tokens: 256,
    messages: [{ role: 'user', content: task }],
  });
  const text = msg.content[0].type === 'text' ? msg.content[0].text : '{}';
  const { action } = Action.parse(JSON.parse(text));
  // ok: js-llm-output-to-dangerous-sink
  return execSync(action === 'list' ? 'ls -la' : 'git status').toString();
}

export async function lookupOrder(question: string) {
  const r = await openai.responses.create({ model: 'gpt-4.1-mini', input: question });
  // ok: js-llm-output-to-dangerous-sink
  return pool.query('SELECT * FROM orders WHERE note = $1', [r.output_text]);
}

export async function findOrderNumber(question: string) {
  const r = await openai.responses.create({ model: 'gpt-4.1-mini', input: question });
  // ok: js-llm-output-to-dangerous-sink
  return /\d+/.exec(r.output_text);
}

export async function agentAsync(task: string) {
  const r = await openai.responses.create({ model: 'gpt-4.1-mini', input: `bash for: ${task}` });
  // ruleid: js-llm-output-to-dangerous-sink
  const { stdout } = await run(r.output_text);
  return stdout;
}

export async function agentAsyncSafe(task: string) {
  const r = await openai.responses.create({ model: 'gpt-4.1-mini', input: task });
  const n = Number(r.output_text);
  // ok: js-llm-output-to-dangerous-sink
  const { stdout } = await run(`seq 1 ${n}`);
  return stdout;
}
