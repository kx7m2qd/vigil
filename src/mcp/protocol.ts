/**
 * Minimal MCP server: JSON-RPC 2.0 over stdio, one message per line. Tools only.
 * Hand-written on purpose (no SDK): Vigil keeps zero runtime dependencies. See docs/specs/mcp-server.md.
 */
import { createInterface } from "node:readline";
import type { Readable, Writable } from "node:stream";

/** Newest first. We answer with the client's version when we know it, else our newest. */
export const PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

export interface Tool {
  name: string;
  title?: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations?: Record<string, unknown>;
  handler: (args: Record<string, unknown>) => Promise<unknown>;
}

/** A problem with the tool call itself (bad argument, unknown id): shown to the model, not a crash. */
export class ToolError extends Error {}

export interface ServerInfo {
  name: string;
  version: string;
  instructions?: string;
}

type Id = string | number | null;
type Message = Record<string, unknown>;

const PARSE_ERROR = -32700;
const INVALID_REQUEST = -32600;
const METHOD_NOT_FOUND = -32601;
const INVALID_PARAMS = -32602;
const INTERNAL_ERROR = -32603;

class RpcError extends Error {
  constructor(
    readonly code: number,
    message: string,
  ) {
    super(message);
  }
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isId = (v: unknown): v is Id => typeof v === "string" || typeof v === "number" || v === null;

/** Tool results are JSON, sent as one text block. */
function textResult(value: unknown, isError = false): Message {
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return { content: [{ type: "text", text }], ...(isError ? { isError: true } : {}) };
}

export function serve(
  info: ServerInfo,
  tools: Tool[],
  io: { input: Readable; output: Writable; log?: (line: string) => void },
): Promise<void> {
  const byName = new Map(tools.map((t) => [t.name, t]));
  const log = io.log ?? (() => {});
  const send = (msg: Message): void => {
    io.output.write(JSON.stringify({ jsonrpc: "2.0", ...msg }) + "\n");
  };

  async function handle(method: string, params: Record<string, unknown>): Promise<unknown> {
    switch (method) {
      case "initialize": {
        const asked = params.protocolVersion;
        const protocolVersion = typeof asked === "string" && PROTOCOL_VERSIONS.includes(asked) ? asked : PROTOCOL_VERSIONS[0];
        return {
          protocolVersion,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: info.name, version: info.version },
          ...(info.instructions ? { instructions: info.instructions } : {}),
        };
      }
      case "ping":
        return {};
      case "tools/list":
        return {
          tools: tools.map(({ handler: _, ...t }) => t),
        };
      case "tools/call": {
        const name = params.name;
        const tool = typeof name === "string" ? byName.get(name) : undefined;
        if (!tool) throw new RpcError(INVALID_PARAMS, `Unknown tool: ${String(name)}`);
        const args = params.arguments ?? {};
        if (!isObject(args)) throw new RpcError(INVALID_PARAMS, "arguments must be an object");
        try {
          return textResult(await tool.handler(args));
        } catch (e) {
          if (!(e instanceof ToolError)) log(`tool ${tool.name} failed: ${e instanceof Error ? (e.stack ?? e.message) : String(e)}`);
          return textResult(e instanceof Error ? e.message : String(e), true);
        }
      }
      default:
        throw new RpcError(METHOD_NOT_FOUND, `Method not found: ${method}`);
    }
  }

  const pending = new Set<Promise<void>>();

  function onLine(line: string): void {
    if (!line.trim()) return;
    let msg: unknown;
    try {
      msg = JSON.parse(line);
    } catch {
      send({ id: null, error: { code: PARSE_ERROR, message: "Parse error" } });
      return;
    }
    if (!isObject(msg)) {
      // Batches were removed from MCP in 2025-06-18; anything that isn't one object is invalid.
      send({ id: null, error: { code: INVALID_REQUEST, message: "Invalid request" } });
      return;
    }
    const hasId = "id" in msg;
    if (typeof msg.method !== "string") {
      // A response to something we never send (we make no requests), or garbage: nothing to answer.
      if (hasId && !("result" in msg || "error" in msg)) {
        send({ id: isId(msg.id) ? msg.id : null, error: { code: INVALID_REQUEST, message: "Invalid request" } });
      }
      return;
    }
    if (!hasId) return; // notification (notifications/initialized, cancelled, ...): no reply
    const id = msg.id;
    if (msg.jsonrpc !== "2.0" || !isId(id)) {
      send({ id: isId(id) ? id : null, error: { code: INVALID_REQUEST, message: "Invalid request" } });
      return;
    }
    const params = msg.params ?? {};
    const method = msg.method;
    const p = (async () => {
      if (!isObject(params)) throw new RpcError(INVALID_PARAMS, "params must be an object");
      return handle(method, params);
    })().then(
      (result) => send({ id, result }),
      (e: unknown) => {
        if (e instanceof RpcError) send({ id, error: { code: e.code, message: e.message } });
        else {
          log(`${method} failed: ${e instanceof Error ? (e.stack ?? e.message) : String(e)}`);
          send({ id, error: { code: INTERNAL_ERROR, message: "Internal error" } });
        }
      },
    );
    const tracked: Promise<void> = p.finally(() => pending.delete(tracked));
    pending.add(tracked);
  }

  return new Promise((resolveDone) => {
    const rl = createInterface({ input: io.input, crlfDelay: Infinity });
    rl.on("line", onLine);
    rl.on("close", () => {
      void Promise.all(pending).then(() => resolveDone());
    });
  });
}
