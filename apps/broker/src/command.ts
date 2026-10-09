import type { OperationRequest } from "../../../protocol/src/index.ts";

// Fail closed. Every accepted argument must have a known effect on the target.
export function commandTarget(operation: OperationRequest): { vault: string; item?: string } {
  const args = operation.args;
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== "string" || /[\0\r\n]/.test(arg))) {
    throw new Error("Invalid command arguments");
  }
  const referenceRead = args[0] === "read" && operation.operation === "read";
  const subcommand = { read: "get", list: "list", write: "edit", create: "create", delete: "delete", execute: "" }[operation.operation];
  if (!referenceRead && (!subcommand || args[0] !== "item" || args[1] !== subcommand)) {
    throw new Error(`Command does not match the ${operation.operation} operation`);
  }
  const flags = new Map<string, string>();
  const positional: string[] = [];
  const permitted = referenceRead ? ["--no-newline"] : ["--vault", "--format",
    ...(subcommand === "get" ? ["--fields", "--reveal"] : []),
    ...(subcommand === "create" ? ["--title", "--category"] : []),
    ...(subcommand === "delete" ? ["--archive"] : [])];
  for (let i = referenceRead ? 1 : 2; i < args.length; i++) {
    const arg = args[i];
    if (!arg.startsWith("-")) { positional.push(arg); continue; }
    const separator = arg.indexOf("=");
    const key = separator < 0 ? arg : arg.slice(0, separator);
    if (!permitted.includes(key) || flags.has(key)) throw new Error("Unsupported or duplicate command flag");
    const boolean = ["--no-newline", "--reveal", "--archive"].includes(key);
    const value = separator >= 0 ? arg.slice(separator + 1) : boolean ? "true" : args[++i];
    if (!value || value.startsWith("-") || (boolean && value !== "true")) throw new Error("Invalid command flag value");
    flags.set(key, value);
  }
  if (flags.has("--format") && flags.get("--format") !== "json") throw new Error("Only JSON output is supported");
  let vault: string | undefined;
  let item: string | undefined;
  if (referenceRead) {
    if (positional.length !== 1 || !positional[0].startsWith("op://")) throw new Error("Read needs one secret reference");
    const parts = positional[0].slice(5).split("/");
    if (parts.length < 3 || parts.length > 4 || parts.some((part) => !part || /[%?#\\]/.test(part))) {
      throw new Error("Invalid secret reference");
    }
    [vault, item] = parts;
    if (operation.field && operation.field !== parts.slice(2).join("/")) throw new Error("Field does not match command");
  } else {
    vault = flags.get("--vault");
    const needsItem = ["get", "edit", "delete"].includes(subcommand);
    if (needsItem) item = positional.shift();
    if (needsItem && !item) throw new Error("Command must name one item");
    const assignments = ["edit", "create"].includes(subcommand);
    if (positional.length && (!assignments || positional.some((arg) => !/^[^=]+=.*/s.test(arg)))) {
      throw new Error("Unexpected command arguments");
    }
    if (operation.field && flags.get("--fields") !== operation.field) throw new Error("Field does not match command");
  }
  if (!vault || vault === "*" || vault !== operation.vault) throw new Error("Vault does not match command");
  if (operation.itemId && operation.itemId !== item) throw new Error("Item does not match command");
  return { vault, item };
}
