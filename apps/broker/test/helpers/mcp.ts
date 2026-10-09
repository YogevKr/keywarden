import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";

// Synthetic integration client. Never log tool responses or command output.
export class McpClient {
  readonly process: ChildProcessWithoutNullStreams;
  readonly errors: Buffer[] = [];
  private nextId = 0;
  private pending = new Map<number, { resolve: (value: any) => void; reject: (error: Error) => void }>();

  constructor(binary: string, socket: string) {
    this.process = spawn(binary, ["mcp"], { env: { KEYWARDEN_SOCKET: socket }, stdio: ["pipe", "pipe", "pipe"] });
    this.process.stderr.on("data", (chunk: Buffer) => this.errors.push(chunk));
    createInterface({ input: this.process.stdout }).on("line", (line) => {
      try {
        const response = JSON.parse(line);
        const pending = this.pending.get(response.id);
        if (!pending) throw new Error("Unexpected MCP response");
        this.pending.delete(response.id);
        if (response.error) pending.reject(new Error(response.error.message));
        else pending.resolve(response.result);
      } catch {
        for (const pending of this.pending.values()) pending.reject(new Error("Invalid MCP response"));
        this.pending.clear();
      }
    });
    this.process.on("error", () => this.fail("MCP process failed"));
    this.process.on("exit", () => this.fail("MCP process exited"));
  }

  private fail(message: string) {
    for (const pending of this.pending.values()) pending.reject(new Error(message));
    this.pending.clear();
  }

  request(method: string, params: unknown = {}): Promise<any> {
    const id = ++this.nextId;
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error("MCP request timed out"));
      }, 15_000);
      this.pending.set(id, {
        resolve: (value) => { clearTimeout(timeout); resolve(value); },
        reject: (error) => { clearTimeout(timeout); reject(error); },
      });
      this.process.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    });
  }

  async initialize(clientInfo: { name: string; version: string; title?: string } = { name: "code-mode-test", version: "1" }) {
    const result = await this.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo });
    this.process.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    return result;
  }

  call(name: string, args: unknown = {}) { return this.request("tools/call", { name, arguments: args }); }

  async close() {
    if (this.process.exitCode !== null || this.process.signalCode !== null) return;
    await new Promise<void>((resolve) => {
      this.process.once("exit", () => resolve());
      this.process.kill("SIGTERM");
    });
  }
}
