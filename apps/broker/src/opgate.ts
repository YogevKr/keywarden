import { spawn } from "node:child_process";
import type { AccountName } from "../../../protocol/src/index.ts";

export interface OpGateResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
let brokerToken: string | undefined;

export function setBrokerToken(token: string): void {
  brokerToken = token;
}

export function getBrokerToken(): string | undefined {
  return brokerToken;
}

export function opgateProfileForAccount(profile: AccountName): string {
  switch (profile) {
    case "agent":
      return process.env.KEYWARDEN_OPGATE_PROFILE ?? "agent";
    case "personal":
      return process.env.KEYWARDEN_OPGATE_PERSONAL_PROFILE ?? "keywarden-personal";
    case "work":
      return process.env.KEYWARDEN_OPGATE_WORK_PROFILE ?? "keywarden-work";
  }
}

export async function runOpGate(profile: AccountName, args: string[]): Promise<OpGateResult> {
  for (const arg of args) {
    if (arg.includes("\u0000")) throw new Error("Operation contains a NUL byte");
  }
  const opgateProfile = opgateProfileForAccount(profile);
  const opgateMode = Boolean(process.env.KEYWARDEN_OPGATE_PROFILE || process.env.KEYWARDEN_OPGATE_PERSONAL_PROFILE || process.env.KEYWARDEN_OPGATE_WORK_PROFILE);
  const token = brokerToken;
  if (!token && !opgateMode) throw new Error("Broker service token is not loaded");
  if (!opgateMode && profile !== "agent") throw new Error("Personal and work accounts need opgate profiles");
  const binary = process.env.KEYWARDEN_OP_BIN ?? (opgateMode ? "opgate" : "op");
  const commandArgs = opgateMode ? ["op", "--profile", opgateProfile, "--", ...args] : args;
  return new Promise((resolve, reject) => {
    const childEnv = { ...process.env };
    for (const name of Object.keys(childEnv)) {
      if (name.startsWith("KEYWARDEN_")) delete childEnv[name];
    }
    if (opgateMode) delete childEnv.OP_SERVICE_ACCOUNT_TOKEN;
    else if (token) childEnv.OP_SERVICE_ACCOUNT_TOKEN = token;
    const child = spawn(binary, commandArgs, {
      env: childEnv,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let total = 0;
    let overflow = false;
    const collect = (target: Buffer[]) => (chunk: Buffer) => {
      total += chunk.length;
      if (total > MAX_OUTPUT_BYTES) {
        overflow = true;
        child.kill("SIGTERM");
        return;
      }
      target.push(chunk);
    };
    child.stdout.on("data", collect(stdout));
    child.stderr.on("data", collect(stderr));
    child.on("error", reject);
    child.on("close", (code, signal) => {
      if (overflow) {
        reject(new Error("opgate output exceeded the broker limit"));
        return;
      }
      resolve({
        exitCode: code ?? (signal ? 128 : 1),
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    });
  });
}
