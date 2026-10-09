import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { opgateProfileForAccount, runOpGate, setBrokerToken } from "../src/opgate.ts";

test("broker passes the in-memory token only to the op child", async () => {
  const directory = await mkdtemp(join(tmpdir(), "keywarden-op-test-"));
  const fakeOp = join(directory, "op");
  await writeFile(fakeOp, "#!/bin/sh\n[ \"$OP_SERVICE_ACCOUNT_TOKEN\" = test-token ] || exit 7\nprintf '%s' \"$*\"\n", { mode: 0o700 });
  await chmod(fakeOp, 0o700);
  const previousBin = process.env.KEYWARDEN_OP_BIN;
  process.env.KEYWARDEN_OP_BIN = fakeOp;
  setBrokerToken("test-token");
  try {
    const result = await runOpGate("agent", ["item", "list", "--vault", "agents"]);
    assert.equal(result.exitCode, 0);
    assert.equal(result.stdout, "item list --vault agents");
  } finally {
    if (previousBin === undefined) delete process.env.KEYWARDEN_OP_BIN;
    else process.env.KEYWARDEN_OP_BIN = previousBin;
    await rm(directory, { recursive: true, force: true });
  }
});

test("broker can use the local opgate adapter without a token environment", async () => {
  const directory = await mkdtemp(join(tmpdir(), "keywarden-opgate-test-"));
  const fakeOp = join(directory, "opgate");
  await writeFile(fakeOp, "#!/bin/sh\n[ \"$OP_SERVICE_ACCOUNT_TOKEN\" = \"\" ] || exit 9\nprintf '%s' \"$*\"\n", { mode: 0o700 });
  await chmod(fakeOp, 0o700);
  const previousBin = process.env.KEYWARDEN_OP_BIN;
  const previousProfile = process.env.KEYWARDEN_OPGATE_PROFILE;
  setBrokerToken("");
  delete process.env.KEYWARDEN_OP_SERVICE_ACCOUNT_TOKEN;
  process.env.KEYWARDEN_OP_BIN = fakeOp;
  process.env.KEYWARDEN_OPGATE_PROFILE = "agent";
  try {
    const result = await runOpGate("agent", ["item", "list", "--vault", "agents"]);
    assert.equal(result.exitCode, 0);
    assert.equal(result.stdout, "op --profile agent -- item list --vault agents");
  } finally {
    if (previousBin === undefined) delete process.env.KEYWARDEN_OP_BIN;
    else process.env.KEYWARDEN_OP_BIN = previousBin;
    if (previousProfile === undefined) delete process.env.KEYWARDEN_OPGATE_PROFILE;
    else process.env.KEYWARDEN_OPGATE_PROFILE = previousProfile;
    await rm(directory, { recursive: true, force: true });
  }
});

test("broker maps approved account names to dedicated opgate profiles", async () => {
  assert.equal(opgateProfileForAccount("agent"), process.env.KEYWARDEN_OPGATE_PROFILE ?? "agent");
  assert.equal(opgateProfileForAccount("personal"), process.env.KEYWARDEN_OPGATE_PERSONAL_PROFILE ?? "keywarden-personal");
  assert.equal(opgateProfileForAccount("work"), process.env.KEYWARDEN_OPGATE_WORK_PROFILE ?? "keywarden-work");
});

test("personal operations use the personal service-account profile", async () => {
  const directory = await mkdtemp(join(tmpdir(), "keywarden-op-personal-test-"));
  const fakeOp = join(directory, "opgate");
  await writeFile(fakeOp, "#!/bin/sh\nprintf '%s' \"$*\"\n", { mode: 0o700 });
  await chmod(fakeOp, 0o700);
  const previousBin = process.env.KEYWARDEN_OP_BIN;
  const previousProfile = process.env.KEYWARDEN_OPGATE_PROFILE;
  const previousPersonal = process.env.KEYWARDEN_OPGATE_PERSONAL_PROFILE;
  setBrokerToken("");
  process.env.KEYWARDEN_OP_BIN = fakeOp;
  process.env.KEYWARDEN_OPGATE_PROFILE = "agent";
  delete process.env.KEYWARDEN_OPGATE_PERSONAL_PROFILE;
  try {
    const result = await runOpGate("personal", ["item", "list", "--vault", "Keywarden Personal"]);
    assert.equal(result.exitCode, 0);
    assert.equal(result.stdout, "op --profile keywarden-personal -- item list --vault Keywarden Personal");
  } finally {
    if (previousBin === undefined) delete process.env.KEYWARDEN_OP_BIN;
    else process.env.KEYWARDEN_OP_BIN = previousBin;
    if (previousProfile === undefined) delete process.env.KEYWARDEN_OPGATE_PROFILE;
    else process.env.KEYWARDEN_OPGATE_PROFILE = previousProfile;
    if (previousPersonal === undefined) delete process.env.KEYWARDEN_OPGATE_PERSONAL_PROFILE;
    else process.env.KEYWARDEN_OPGATE_PERSONAL_PROFILE = previousPersonal;
    await rm(directory, { recursive: true, force: true });
  }
});
