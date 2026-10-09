import assert from "node:assert/strict";
import { createServer, request as httpRequest } from "node:http";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { spawn, type ChildProcess } from "node:child_process";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { McpClient } from "./helpers/mcp.ts";
import test from "node:test";
import {
  decryptWithPrivateKey,
  encryptForPublicKey,
  exportPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  hashRequest,
  importEncryptionPrivateKey,
  signEnvelope,
  verifyEnvelope,
} from "../../../protocol/src/index.ts";
import type { JsonValue, SignedEnvelope } from "../../../protocol/src/index.ts";

const RELAY_TOKEN = "relay-test-token";

interface RelayEntry {
  requestId: string;
  phoneId: string;
  expiresAt: string;
  envelope: SignedEnvelope;
  decision?: SignedEnvelope;
  status?: SignedEnvelope;
  revocation?: SignedEnvelope;
  decisionFailures?: number;
}

test("local broker, opaque relay, phone approval, and op execution work end to end", async () => {
  const directory = await mkdtemp(join(tmpdir(), "keywarden-e2e-"));
  const socketPath = join(directory, "broker.sock");
  const fakeOp = join(directory, "op");
  const relayEntries = new Map<string, RelayEntry>();
  const relay = createLocalRelay(relayEntries);
  const relayPort = await listen(relay);
  const relayURL = `http://127.0.0.1:${relayPort}`;
  let broker: ChildProcess | undefined;
  let mcp: McpClient | undefined;
  const rustBinary = process.env.KEYWARDEN_E2E_BROKER_EXEC;
  const account = rustBinary ? "personal" : "agent";
  const secretValue = 'synthetic-only\nvalue with "quotes" and spaces\n';

  try {
    await writeFile(
      fakeOp,
      "#!/bin/sh\n" +
        (rustBinary
          ? '[ "$1" = op ] && [ "$2" = --profile ] && { [ "$3" = keywarden-personal ] || [ "$3" = agent ]; } && [ "$4" = -- ] || exit 17\nshift 4\n'
          : "[ \"$OP_SERVICE_ACCOUNT_TOKEN\" = service-token ] || exit 17\n") +
        'if [ "$1 $2" = "vault get" ]; then name="${3%-vaultid}"; printf \'{"id":"%s-vaultid","name":"%s"}\' "$name" "$name"; exit 0; fi\n' +
        'if [ "$1 $2" = "vault list" ]; then printf \'[{"id":"agents-vaultid","name":"agents"},{"id":"other-vaultid","name":"other"}]\'; exit 0; fi\n' +
        'if [ "$1 $2" = "item get" ] && [ "$6" = "--format=json" ]; then printf \'{"id":"item-1","title":"Example","fields":[{"id":"username","label":"username","type":"STRING","value":"hidden-user"},{"id":"password","label":"password","type":"CONCEALED","value":"hidden-secret","section":{"id":"login","label":"Login"}}]}\'; exit 0; fi\n' +
        'if [ "$1" = read ]; then\n' +
        '  if [ "$2" = op://agents/fail/password ] || [ "$2" = op://agents-vaultid/fail/password ]; then printf "sensitive-error-canary" >&2; printf "sensitive-error-canary"; exit 9; fi\n' +
        '  if [ "$2" = op://agents-vaultid/missing/password ]; then printf "item not found: sensitive-error-canary" >&2; exit 1; fi\n' +
        `  printf '%s' '${secretValue}'; exit 0\nfi\n` +
        'if [ "$1 $2" = "item list" ]; then printf \'[{"id":"item-1","title":"Example","additional_information":"private-note-canary","vault":{"id":"agents-vaultid"}}]\'; exit 0; fi\n' +
        "printf 'fake-op-ok:%s' \"$*\"\n",
      { mode: 0o700 },
    );
    await chmod(fakeOp, 0o700);

    const phoneSigning = await generateSigningKeyPair();
    const phoneEncryption = await generateEncryptionKeyPair();
    const phoneSigningPublic = await exportPublicKey(phoneSigning.publicKey);
    const phoneEncryptionPublic = await exportPublicKey(phoneEncryption.publicKey);

    broker = spawn(
      process.env.KEYWARDEN_E2E_BROKER_EXEC ?? process.execPath,
      process.env.KEYWARDEN_E2E_BROKER_EXEC ? ["serve", "--token-stdin"] : ["--experimental-strip-types", fileURLToPath(new URL("../src/index.ts", import.meta.url)), "serve", "--token-stdin"],
      {
        env: {
          ...process.env,
          KEYWARDEN_STATE_DIR: join(directory, "state"),
          KEYWARDEN_SOCKET: socketPath,
          KEYWARDEN_OP_BIN: fakeOp,
          KEYWARDEN_RELAY_URL: relayURL,
          KEYWARDEN_RELAY_TOKEN: RELAY_TOKEN,
          KEYWARDEN_PHONE_ID: "phone-1",
          KEYWARDEN_PHONE_SIGNING_PUBLIC_JWK: JSON.stringify(phoneSigningPublic),
          KEYWARDEN_PHONE_ENCRYPTION_PUBLIC_JWK: JSON.stringify(phoneEncryptionPublic),
          ...(rustBinary ? { KEYWARDEN_OPGATE_PROFILE: "agent", KEYWARDEN_OPGATE_PERSONAL_PROFILE: "keywarden-personal" } : {}),
        },
        stdio: ["pipe", "ignore", "pipe"],
      },
    );
    const brokerErrors: Buffer[] = [];
    broker.stderr?.on("data", (chunk: Buffer) => brokerErrors.push(chunk));
    broker.stdin?.end("service-token\n");

    await waitForSocket(socketPath);
    const identity = await socketJSON<{ brokerId: string; signingPublicJwk: JsonValue; encryptionPublicJwk: JsonValue }>(socketPath, "GET", "/v1/identity");
    const phonePrivateKey = await importEncryptionPrivateKey(await importPrivateKey(phoneEncryption.privateKey));

    if (rustBinary) {
      mcp = new McpClient(rustBinary, socketPath);
      const initialized = await mcp.initialize({ name: "codex", version: "0.160.0", title: "Deploy API" });
      assert.equal(initialized.serverInfo.title, "Keywarden 1Password for Codex");
      assert.equal((await mcp.request("tools/list")).tools.length, 7);
      const overview = await mcp.call("keywarden_access_status");
      assert.equal(overview.isError, false);
      assert.equal(overview.structuredContent.status, "ready");
      assert.equal(overview.structuredContent.accounts[0].status, "active");
      assert.equal(overview.structuredContent.accounts[1].status, "approval_required");
      assert.equal(overview.structuredContent.providerVerified, false);
      assert.equal(relayEntries.size, 0);
      const vaults = await mcp.call("keywarden_list_vaults");
      assert.equal(vaults.isError, false, vaults.content?.[0]?.text);
      assert.deepEqual(vaults.structuredContent.vaults, [{id:"agents-vaultid",name:"agents"}]);
      const byVaultId = await mcp.call("keywarden_list_items", {vault:"agents-vaultid",account:"agent"});
      assert.equal(byVaultId.isError,false,byVaultId.content?.[0]?.text);
      assert.deepEqual(byVaultId.structuredContent.items,[{id:"item-1",title:"Example"}]);
      assert.equal(JSON.stringify(byVaultId).includes("private-note-canary"),false);
      const missingItem = await mcp.call("keywarden_read_secret",{reference:"op://agents-vaultid/missing/password",account:"agent"});
      assert.equal(missingItem.structuredContent.error.code,"item_not_found");
      assert.equal(JSON.stringify(missingItem).includes("sensitive-error-canary"),false);
      const outsideAgent = await mcp.call("keywarden_list_items",{vault:"other-vaultid",account:"agent",requestIfNeeded:false});
      assert.equal(outsideAgent.isError,true);
      const direct = await mcp.call("keywarden_read_secret", { reference: "op://agents/item-1/password", account: "agent" });
      assert.equal(direct.isError, false, direct.content?.[0]?.text);
      assert.equal(direct.structuredContent.value, secretValue);
      assert.equal(JSON.stringify(direct.content).includes(secretValue), false);
      const directAccess = await mcp.call("keywarden_request_access", { account: "agent", vaults: ["agents"], operations: ["read", "list"], reason: "Use the existing agent scope" });
      assert.equal(directAccess.isError, false);
      assert.equal(directAccess.structuredContent.status, "active");
      assert.equal(directAccess.structuredContent.leaseId, "direct-agent");
      assert.equal(directAccess.structuredContent.client.displayName, "Codex");

      const automatic = await mcp.call("keywarden_list_items", { vault: "agents", account: "personal", waitSeconds: 0 });
      assert.equal(automatic.isError, false);
      assert.equal(automatic.structuredContent.status, "pending");
      const automaticRequestId = automatic.structuredContent.requestId;
      assert.ok(automaticRequestId);
      const automaticEntry = await waitForRelayRequest(relayEntries, automaticRequestId);
      const automaticRequest = JSON.parse(await decryptWithPrivateKey(automaticEntry.envelope.body, phonePrivateKey)) as { scope: { accounts: string[]; vaults: string[]; items: string; operations: string[] } };
      assert.deepEqual(automaticRequest.scope, { accounts: ["personal"], vaults: ["agents"], items: "all", operations: ["list"] });

      const repeated = await mcp.call("keywarden_list_items", { vault: "agents", account: "personal", waitSeconds: 0 });
      assert.equal(repeated.isError, false);
      assert.equal(repeated.structuredContent.status, "pending");
      assert.equal(repeated.structuredContent.requestId, automaticRequestId);
      const pendingOverview = await mcp.call("keywarden_access_status");
      assert.equal(pendingOverview.structuredContent.accounts[1].status, "pending");
      assert.equal(pendingOverview.structuredContent.accounts[1].pendingRequests[0].requestId, automaticRequestId);
      const pendingRead = await mcp.call("keywarden_read_secret", { reference: "op://agents/item-1/password", account: "personal", waitSeconds: 0 });
      assert.equal(pendingRead.isError, false);
      assert.equal(pendingRead.structuredContent.status, "pending");
      assert.equal(pendingRead.structuredContent.value, undefined);
      assert.equal(JSON.stringify(pendingRead).includes(secretValue), false);
      await mcp.call("keywarden_manage_request", { requestId: pendingRead.structuredContent.requestId, action: "cancel" });
      assert.equal(relayEntries.size, 2);

      await mcp.close();
      mcp = new McpClient(rustBinary, socketPath);
      await mcp.initialize({ name: "codex", version: "0.160.0", title: "Deploy API" });
      const repeatedAfterProcessRestart = await mcp.call("keywarden_list_items", { vault: "agents", account: "personal", waitSeconds: 0 });
      assert.equal(repeatedAfterProcessRestart.isError, false);
      assert.equal(repeatedAfterProcessRestart.structuredContent.status, "pending");
      assert.equal(repeatedAfterProcessRestart.structuredContent.requestId, automaticRequestId);
      assert.equal(relayEntries.size, 2);
    }

    type Pending = { request: { id: string; scope: { items: "all" | string[] }; intent?: { task?: string }; client?: { product: string; displayName: string; sessionName?: string; sessionId?: string } }; requestHash: string };
    let pending: Pending;
    if (mcp) {
      const request = await mcp.call("keywarden_request_access", {
        account, vaults: ["agents"], durationSeconds: 30, idleTimeoutSeconds: 10,
        reason: "Read the deployment credential", task: "Deploy the API", sessionName: "Deploy API run #5",
        sessionId: "synthetic-session-5", agent: "codex", host: "MacBook",
      });
      assert.equal(request.isError, false);
      assert.equal(request.structuredContent.status, "pending");
      pending = await socketJSON<Pending>(socketPath, "GET", `/v1/session-requests/${request.structuredContent.requestId}`);
      assert.deepEqual((pending.request.scope as { operations?: string[] }).operations, ["read", "list"]);
    } else {
      pending = await socketJSON<Pending>(socketPath, "POST", "/v1/session-requests", {
      agent: "codex",
      host: "MacBook",
      phoneId: "phone-1",
      reason: "local end to end test",
      scope: { accounts: [account], vaults: ["agents"], items: "all", operations: ["read"] },
      durationSeconds: 30,
      idleTimeoutSeconds: 10,
    });
    }

    await assert.rejects(
      socketJSON(socketPath, "POST", "/v1/operations", {
        version: 1,
        leaseId: "not-approved",
        profile: "agent",
        operation: "read",
        vault: "agents",
        args: ["item", "get"],
      }),
      /Unknown session lease/,
    );

    const relayEntry = await waitForRelayRequest(relayEntries, pending.request.id);
    assert.equal(await verifyEnvelope(relayEntry.envelope), true);
    const request = JSON.parse(await decryptWithPrivateKey(relayEntry.envelope.body, phonePrivateKey)) as typeof pending.request;
    assert.equal(request.scope.items, "all");
    if (mcp) {
      assert.equal(request.intent?.task, "Deploy the API");
      assert.equal(request.client?.product, "codex");
      assert.equal(request.client?.displayName, "Codex");
      assert.equal(request.client?.sessionId, "synthetic-session-5");
      assert.equal(request.client?.sessionName, "Deploy API run #5");
    }
    assert.equal(await hashRequest(request as never), pending.requestHash);

    const decision = {
      version: 1 as const,
      type: "approval_decision" as const,
      requestId: request.id,
      requestHash: pending.requestHash,
      decision: "approve" as const,
      decidedAt: new Date().toISOString(),
      nonce: "local-e2e-decision",
    };
    const decisionBody = await encryptForPublicKey(JSON.stringify(decision), identity.encryptionPublicJwk);
    relayEntry.decision = await signEnvelope("approval_decision", decisionBody, phoneSigning.privateKey, phoneSigningPublic);
    await relayDecision(relayURL, identity.brokerId, relayEntry);

    const approved = await waitForStatus(socketPath, pending.request.id, "approved");
    assert.ok(approved.leaseId);
    const operation = await socketJSON<{ exitCode: number; stdout: string }>(socketPath, "POST", "/v1/operations", {
      version: 1,
      leaseId: approved.leaseId,
      profile: account,
      operation: "read",
      vault: "agents",
      itemId: "item-1",
      args: ["item", "get", "--vault", "agents", "item-1"],
    });
    assert.equal(operation.exitCode, 0);
    assert.equal(operation.stdout, `fake-op-ok:item get --vault ${rustBinary ? "agents-vaultid" : "agents"} item-1`);

    if (mcp) {
      await mcp.close();
      mcp = new McpClient(rustBinary!, socketPath);
      await mcp.initialize({ name: "codex", version: "0.160.0", title: "Deploy API" });
      const reused = await mcp.call("keywarden_request_access", {
        account,
        vaults: ["agents"],
        operations: ["read", "list"],
        durationSeconds: 30,
        idleTimeoutSeconds: 10,
        reason: "Read the deployment credential",
        task: "Deploy the API",
        sessionName: "Deploy API run #5",
        sessionId: "synthetic-session-5",
        agent: "codex",
        host: "MacBook",
      });
      assert.equal(reused.isError, false);
      assert.equal(reused.structuredContent.status, "active");
      assert.equal(reused.structuredContent.requestId, pending.request.id);
      assert.equal(reused.structuredContent.leaseId, approved.leaseId);

      const access = await mcp.call("keywarden_access_status", { requestId: pending.request.id, waitSeconds: 2 });
      assert.equal(access.structuredContent.status, "active");
      const current = await mcp.call("keywarden_access_status");
      assert.equal(current.structuredContent.accounts[1].status, "active");
      assert.ok(current.structuredContent.accounts[1].leases.some((lease: any) => lease.leaseId === approved.leaseId));
      const read = await mcp.call("keywarden_read_secret", { reference: "op://agents/item-1/password", account: "personal" });
      assert.equal(read.isError, false);
      assert.equal(read.structuredContent.value, secretValue);
      assert.equal(JSON.stringify(read.content).includes(secretValue), false);

      // Pipe the returned value to a separate process through stdin. The code
      // host reports only the digest; it never emits the value to its transcript.
      const consumer = spawn(process.execPath, ["-e", "const c=require('node:crypto').createHash('sha256');process.stdin.on('data',x=>c.update(x));process.stdin.on('end',()=>process.stdout.write(c.digest('hex')));"], { stdio: ["pipe", "pipe", "pipe"] });
      const digest: Buffer[] = [];
      consumer.stdout.on("data", (chunk: Buffer) => digest.push(chunk));
      consumer.stdin.end(read.structuredContent.value);
      assert.equal(await new Promise((resolve) => consumer.on("exit", resolve)), 0);
      assert.equal(Buffer.concat(digest).toString(), createHash("sha256").update(secretValue).digest("hex"));

      const list = await mcp.call("keywarden_list_items", { vault: "agents", account: "personal" });
      assert.deepEqual(list.structuredContent.items, [{ id: "item-1", title: "Example" }]);
      assert.deepEqual(JSON.parse(list.content[0].text), list.structuredContent);
      const fields = await mcp.call("keywarden_list_fields", { vault: "agents", item: "item-1", account: "personal" });
      assert.equal(fields.isError, false);
      assert.equal(fields.structuredContent.fields[1].label, "password");
      assert.equal(fields.structuredContent.fields[1].reference, "op://agents/item-1/login/password");
      assert.deepEqual(JSON.parse(fields.content[0].text), fields.structuredContent);
      assert.equal(JSON.stringify(fields).includes("hidden-secret"), false);
      const failure = await mcp.call("keywarden_read_secret", { reference: "op://agents/fail/password", account: "personal" });
      assert.equal(failure.isError, true);
      assert.equal(JSON.parse(failure.content[0].text).error.code, "op_rejected");
      assert.equal(JSON.stringify(failure).includes("sensitive-error-canary"), false);
      const outside = await mcp.call("keywarden_read_secret", { reference: "op://other/item-1/password", account: "personal", requestIfNeeded: false });
      assert.equal(outside.isError, true);
      const otherAccount = await mcp.call("keywarden_read_secret", { reference: "op://agents/item-1/password", account: "work", requestIfNeeded: false });
      assert.equal(otherAccount.isError, true);
      const storedRelay = JSON.stringify([...relayEntries.values()]);
      assert.equal(storedRelay.includes(secretValue), false);
      assert.equal(storedRelay.includes("service-token"), false);
      assert.equal(storedRelay.includes("sensitive-error-canary"), false);

      // Exercise the installed CLI contract against the same isolated broker,
      // encrypted relay, synthetic phone, and provider used by MCP.
      const cliRequest = await runCLI(rustBinary!, socketPath, [
        "request-session", "--account", "personal", "--vault", "cli-vault",
        "--reason", "Read the test field and list its vault", "--task", "CLI parity test",
        "--session-name", "CLI test session", "--duration", "30", "--idle-timeout", "10", "--no-wait",
      ]);
      assert.equal(cliRequest.code, 0, cliRequest.stderr);
      const cliPending = JSON.parse(cliRequest.stdout);
      assert.equal(cliPending.request.agent, "Codex");
      assert.equal(cliPending.request.client.product, "codex");
      assert.equal(cliPending.request.client.transport, "cli");
      assert.equal(cliPending.request.client.sessionName, "CLI test session");
      assert.equal(cliPending.request.intent.task, "CLI parity test");
      assert.deepEqual(cliPending.request.scope.operations, ["read", "list"]);
      const cliEntry = await waitForRelayRequest(relayEntries, cliPending.request.id);
      const cliDecoded = JSON.parse(await decryptWithPrivateKey(cliEntry.envelope.body, phonePrivateKey));
      assert.equal(cliDecoded.client.displayName, "Codex");
      assert.equal(await verifyEnvelope(cliEntry.envelope), true);
      const cliDecision = { ...decision, requestId: cliPending.request.id, requestHash: cliPending.requestHash, nonce: "cli-e2e-decision" };
      cliEntry.decision = await signEnvelope("approval_decision", await encryptForPublicKey(JSON.stringify(cliDecision), identity.encryptionPublicJwk), phoneSigning.privateKey, phoneSigningPublic);
      await relayDecision(relayURL, identity.brokerId, cliEntry);
      const cliApproved = await waitForStatus(socketPath, cliPending.request.id, "approved");
      const cliList = await runCLI(rustBinary!, socketPath, ["op", "--profile", "personal", "--operation", "list", "--vault", "cli-vault", "--", "item", "list", "--vault", "cli-vault", "--format=json"]);
      assert.equal(cliList.code, 0, cliList.stderr);
      assert.deepEqual(JSON.parse(cliList.stdout), [{ id: "item-1", title: "Example" }]);
      const cliRead = await runCLI(rustBinary!, socketPath, ["op", "--profile", "personal", "--operation", "read", "--vault", "cli-vault", "--item", "item-1", "--", "read", "op://cli-vault/item-1/password", "--no-newline"]);
      assert.equal(cliRead.code, 0, cliRead.stderr);
      assert.equal(cliRead.stdout, secretValue);
      const simpleRead = await runCLI(rustBinary!, socketPath, ["read", "op://cli-vault/item-1/password", "--account", "personal", "--no-request"]);
      assert.equal(simpleRead.code, 0, simpleRead.stderr);
      assert.equal(simpleRead.stdout, secretValue);
      assert.equal(simpleRead.stderr, "");
      const simpleJsonRead = await runCLI(rustBinary!, socketPath, ["read", "op://agents/item-1/password", "--json"]);
      assert.equal(simpleJsonRead.code, 0, simpleJsonRead.stderr);
      assert.equal(JSON.parse(simpleJsonRead.stdout).value, secretValue);
      const simpleList = await runCLI(rustBinary!, socketPath, ["list", "--vault", "cli-vault", "--account", "personal", "--no-request"]);
      assert.equal(simpleList.code, 0, simpleList.stderr);
      assert.deepEqual(JSON.parse(simpleList.stdout).items, [{ id: "item-1", title: "Example" }]);
      const simpleFields = await runCLI(rustBinary!, socketPath, ["fields", "--vault", "cli-vault", "--item", "item-1", "--account", "personal", "--no-request"]);
      assert.equal(simpleFields.code, 0, simpleFields.stderr);
      assert.equal(JSON.parse(simpleFields.stdout).fields[1].reference, "op://cli-vault/item-1/login/password");
      assert.equal(simpleFields.stdout.includes("hidden-secret"), false);
      const simpleFailure = await runCLI(rustBinary!, socketPath, ["read", "op://agents/fail/password"]);
      assert.notEqual(simpleFailure.code, 0);
      assert.equal(simpleFailure.stdout, "");
      assert.equal(JSON.parse(simpleFailure.stderr).error.code, "op_rejected");
      assert.equal(simpleFailure.stderr.includes("sensitive-error-canary"), false);
      const mcpListOnCliLease = await mcp.call("keywarden_list_items", { account: "personal", vault: "cli-vault", requestIfNeeded: false });
      assert.equal(mcpListOnCliLease.isError, false);
      assert.deepEqual(mcpListOnCliLease.structuredContent.items, [{ id: "item-1", title: "Example" }]);
      const mcpReadOnCliLease = await mcp.call("keywarden_read_secret", { account: "personal", reference: "op://cli-vault/item-1/password", requestIfNeeded: false });
      assert.equal(mcpReadOnCliLease.isError, false);
      assert.equal(mcpReadOnCliLease.structuredContent.value, secretValue);
      const blockedWrite = await runCLI(rustBinary!, socketPath, ["op", "--lease", cliApproved.leaseId!, "--profile", "personal", "--operation", "delete", "--vault", "cli-vault", "--item", "item-1", "--", "item", "delete", "item-1", "--vault", "cli-vault"]);
      assert.notEqual(blockedWrite.code, 0);
      assert.match(blockedWrite.stderr, /Operation is outside the lease scope/);
      const narrow = await runCLI(rustBinary!, socketPath, ["request-session", "--account", "personal", "--vault", "narrow-vault", "--operation", "read", "--reason", "Read only", "--no-wait"]);
      assert.equal(narrow.code, 0, narrow.stderr);
      assert.deepEqual(JSON.parse(narrow.stdout).request.scope.operations, ["read"]);
      const cancelledId = JSON.parse(narrow.stdout).request.id;
      const retry = await mcp.call("keywarden_manage_request",{requestId:cancelledId,action:"retry"});
      assert.equal(retry.structuredContent.requestId,cancelledId);
      assert.equal(retry.structuredContent.delivery.relay.state,"accepted");
      assert.equal(retry.structuredContent.delivery.push.state,"disabled");
      assert.equal(retry.structuredContent.delivery.phoneReceipt,"unconfirmed");
      const throttled = await mcp.call("keywarden_manage_request",{requestId:cancelledId,action:"retry"});
      assert.equal(throttled.isError,true);
      const cancelled = await mcp.call("keywarden_manage_request",{requestId:cancelledId,action:"cancel"});
      assert.equal(cancelled.structuredContent.status,"cancelled");
      assert.equal(cancelled.structuredContent.leaseId,null);
      const cancelledEntry = await waitForRelayRequest(relayEntries,cancelledId);
      const lateDecision = {...decision,requestId:cancelledId,requestHash:JSON.parse(narrow.stdout).requestHash,nonce:"late-cancelled-decision"};
      cancelledEntry.decision=await signEnvelope("approval_decision",await encryptForPublicKey(JSON.stringify(lateDecision),identity.encryptionPublicJwk),phoneSigning.privateKey,phoneSigningPublic);
      await relayDecision(relayURL,identity.brokerId,cancelledEntry);
      await sleep(300);
      const stillCancelled = await socketJSON<any>(socketPath,"GET",`/v1/session-requests/${cancelledId}`);
      assert.equal(stillCancelled.session.status,"cancelled");
      assert.equal(stillCancelled.leaseId,undefined);

      // A single CLI operation requests approval and resumes after the phone decision.
      const simpleArgs = ["list", "--account", "personal", "--vault", "simple-vault", "--reason", "Check command approval"];
      const simplePending = await runCLI(rustBinary!, socketPath, [...simpleArgs, "--wait", "0"]);
      assert.notEqual(simplePending.code, 0);
      assert.equal(simplePending.stdout, "");
      const simpleError = JSON.parse(simplePending.stderr).error;
      assert.equal(simpleError.code, "approval_required");
      const simpleEntry = await waitForRelayRequest(relayEntries, simpleError.requestId);
      simpleEntry.decisionFailures = 1;
      for (let attempt=0; attempt<100; attempt++) {
        const status = await socketJSON<any>(socketPath,"GET",`/v1/session-requests/${simpleError.requestId}`);
        if (status.delivery.poll.state === "retrying") break;
        if (attempt===99) assert.fail("Transient relay failure was not reported");
        await sleep(20);
      }
      const simpleRequest = await socketJSON<Pending>(socketPath, "GET", `/v1/session-requests/${simpleError.requestId}`);
      assert.equal(simpleRequest.request.client?.displayName, "Codex");
      const simpleReuse = await mcp.call("keywarden_list_items", { account: "personal", vault: "simple-vault", waitSeconds: 0 });
      assert.equal(simpleReuse.isError, false);
      assert.equal(simpleReuse.structuredContent.status, "pending");
      assert.equal(simpleReuse.structuredContent.requestId, simpleError.requestId);
      const simpleWaiting = runCLI(rustBinary!, socketPath, [...simpleArgs, "--wait", "10"]);
      await sleep(300);
      const simpleDecision = { ...decision, requestId: simpleError.requestId, requestHash: simpleRequest.requestHash, nonce: "simple-command-decision" };
      simpleEntry.decision = await signEnvelope("approval_decision", await encryptForPublicKey(JSON.stringify(simpleDecision), identity.encryptionPublicJwk), phoneSigning.privateKey, phoneSigningPublic);
      await relayDecision(relayURL, identity.brokerId, simpleEntry);
      const simpleCompleted = await simpleWaiting;
      assert.equal(simpleCompleted.code, 0, simpleCompleted.stderr);
      assert.deepEqual(JSON.parse(simpleCompleted.stdout).items, [{ id: "item-1", title: "Example" }]);
      const recovered = await socketJSON<any>(socketPath,"GET",`/v1/session-requests/${simpleError.requestId}`);
      assert.equal(recovered.delivery.poll.state,"decision_received");
      const approvedVaults = await mcp.call("keywarden_list_vaults",{account:"personal",requestIfNeeded:false,query:"simple"});
      assert.equal(approvedVaults.isError,false);
      assert.deepEqual(approvedVaults.structuredContent.vaults,[{id:"simple-vault-vaultid",name:"simple-vault"}]);
      const simpleScopeDenied = await runCLI(rustBinary!, socketPath, ["read", "op://simple-vault/item-1/password", "--account", "personal", "--no-request"]);
      assert.notEqual(simpleScopeDenied.code, 0);
      assert.equal(simpleScopeDenied.stdout, "");
      assert.equal(JSON.parse(simpleScopeDenied.stderr).error.code, "lease_required");
    }

    const revokeBody = await encryptForPublicKey(JSON.stringify({version: 1, type: "session_revoke", requestId: request.id, requestHash: pending.requestHash, decidedAt: new Date().toISOString(), nonce: "test-revoke"}), identity.encryptionPublicJwk);
    relayEntry.revocation = await signEnvelope("session_revoke", revokeBody, phoneSigning.privateKey, phoneSigningPublic);
    for (let attempt = 0; attempt < 200; attempt++) {
      if (relayEntry.status) {
        assert.equal(await verifyEnvelope(relayEntry.status), true);
        const status = JSON.parse(await decryptWithPrivateKey(relayEntry.status.body, phonePrivateKey));
        if (status.status === "revoked") break;
      }
      await sleep(25);
      if (attempt === 199) assert.fail("Remote revocation did not reach the broker");
    }
    await assert.rejects(
      socketJSON(socketPath, "POST", "/v1/operations", {
        version: 1,
        leaseId: approved.leaseId,
        profile: "agent",
        operation: "read",
        vault: "agents",
        args: ["item", "get"],
      }),
      /Session lease is revoked/,
    );

    if (mcp) {
      const blocked = await mcp.call("keywarden_read_secret", { reference: "op://agents/item-1/password", account: "personal" });
      assert.equal(blocked.isError, true);
      assert.match(blocked.content[0].text, /Session lease is revoked/);
      const status = await mcp.call("keywarden_access_status", { requestId: request.id });
      assert.equal(status.structuredContent.status, "revoked");
      assert.equal(Buffer.concat(mcp.errors).toString(), "");
    }

    assert.equal(brokerErrors.join(""), "");
  } finally {
    await mcp?.close();
    broker?.kill("SIGTERM");
    await closeChild(broker);
    await closeServer(relay);
    await rm(directory, { recursive: true, force: true });
  }
});

async function runCLI(binary: string, socket: string, args: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const child = spawn(binary, args, { env: { KEYWARDEN_SOCKET: socket, CODEX_THREAD_ID: "cli-e2e-thread" }, stdio: ["ignore", "pipe", "pipe"] });
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
  const timer = setTimeout(() => child.kill("SIGKILL"), 15_000);
  try {
    const code = await new Promise<number | null>((resolve, reject) => {
      child.once("error", reject);
      child.once("close", resolve);
    });
    return { code, stdout: Buffer.concat(stdout).toString(), stderr: Buffer.concat(stderr).toString() };
  } finally { clearTimeout(timer); }
}

function createLocalRelay(entries: Map<string, RelayEntry>) {
  return createServer(async (request, response) => {
    try {
      if (request.headers.authorization !== `Bearer ${RELAY_TOKEN}`) return send(response, 401, { error: "Unauthorized" });
      const url = new URL(request.url ?? "/", "http://relay.local");
      const segments = url.pathname.split("/").filter(Boolean).map(decodeURIComponent);
      if (segments.length === 6 && segments[3] === "requests" && ["status", "revocation"].includes(segments[5])) {
        const entry = entries.get(segments[4]);
        if (!entry) return send(response, 404, {error: "Unknown request"});
        const field = segments[5] as "status" | "revocation";
        if (request.method === "POST") { entry[field] = await readBody(request) as SignedEnvelope; return send(response, 200, {ok:true}); }
        return entry[field] ? send(response, 200, {envelope: entry[field]}) : send(response, 404, {error: "Not available"});
      }
      if (request.method === "POST" && segments.length === 4 && segments[0] === "v1" && segments[1] === "brokers" && segments[3] === "requests") {
        const body = await readBody(request) as RelayEntry;
        entries.set(body.requestId, body);
        return send(response, 200, { ok: true });
      }
      if (request.method === "GET" && segments.length === 7 && segments[0] === "v1" && segments[1] === "brokers" && segments[3] === "phones" && segments[5] === "requests") {
        const phoneId = segments[4];
        return send(response, 200, { requests: [...entries.values()].filter((entry) => entry.phoneId === phoneId && !entry.decision) });
      }
      if (request.method === "POST" && segments.length === 8 && segments[0] === "v1" && segments[1] === "brokers" && segments[3] === "phones" && segments[5] === "requests" && segments[7] === "decision") {
        const entry = entries.get(segments[6]);
        if (!entry) return send(response, 404, { error: "Unknown request" });
        entry.decision = await readBody(request) as SignedEnvelope;
        return send(response, 200, { ok: true });
      }
      if (request.method === "GET" && segments.length === 5 && segments[0] === "v1" && segments[1] === "brokers" && segments[3] === "decisions") {
        const entry = entries.get(segments[4]);
        if (entry?.decisionFailures) { entry.decisionFailures--; return send(response,503,{error:"Temporary relay failure"}); }
        return entry?.decision ? send(response, 200, { envelope: entry.decision }) : send(response, 404, { error: "Decision not available" });
      }
      return send(response, 404, { error: "Not found" });
    } catch (error) {
      return send(response, 400, { error: error instanceof Error ? error.message : String(error) });
    }
  });
}

async function relayDecision(relayURL: string, brokerId: string, entry: RelayEntry): Promise<void> {
  const response = await fetch(`${relayURL}/v1/brokers/${encodeURIComponent(brokerId)}/phones/${encodeURIComponent(entry.phoneId)}/requests/${encodeURIComponent(entry.requestId)}/decision`, {
    method: "POST",
    headers: { authorization: `Bearer ${RELAY_TOKEN}`, "content-type": "application/json" },
    body: JSON.stringify(entry.decision),
  });
  assert.equal(response.status, 200);
}

async function waitForRelayRequest(entries: Map<string, RelayEntry>, requestId: string): Promise<RelayEntry> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const entry = entries.get(requestId);
    if (entry) return entry;
    await sleep(25);
  }
  throw new Error("Broker did not submit a relay request");
}

async function waitForStatus(socketPath: string, requestId: string, expected: string): Promise<{ leaseId?: string }> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const status = await socketJSON<{ status: string; leaseId?: string }>(socketPath, "GET", `/v1/session-requests/${encodeURIComponent(requestId)}`);
    if (status.status === expected) return status;
    await sleep(25);
  }
  throw new Error(`Request did not reach ${expected}`);
}

async function waitForSocket(socketPath: string): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      await socketJSON(socketPath, "GET", "/health");
      return;
    } catch {
      await sleep(25);
    }
  }
  throw new Error("Broker socket did not start");
}

async function socketJSON<T = unknown>(socketPath: string, method: string, path: string, body?: unknown): Promise<T> {
  return new Promise((resolve, reject) => {
    const encoded = body === undefined ? "" : JSON.stringify(body);
    const request = httpRequest({ socketPath, path, method, headers: { "content-type": "application/json", "content-length": Buffer.byteLength(encoded) } }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      response.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        let parsed: any;
        try { parsed = text ? JSON.parse(text) : {}; } catch (error) { reject(error); return; }
        if ((response.statusCode ?? 500) >= 400) reject(new Error(parsed.error ?? `HTTP ${response.statusCode}`));
        else resolve(parsed as T);
      });
    });
    request.on("error", reject);
    if (encoded) request.write(encoded);
    request.end();
  });
}

async function importPrivateKey(key: CryptoKey): Promise<JsonValue> {
  return crypto.subtle.exportKey("jwk", key) as Promise<JsonValue>;
}

async function readBody(request: import("node:http").IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
}

function send(response: import("node:http").ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(body));
}

function listen(server: ReturnType<typeof createServer>): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") return reject(new Error("Relay did not expose a TCP port"));
      resolve(address.port);
    });
  });
}

function closeServer(server: ReturnType<typeof createServer>): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()));
}

function closeChild(child: ChildProcess | undefined): Promise<void> {
  if (!child || child.exitCode !== null) return Promise.resolve();
  return new Promise((resolve) => child.once("exit", () => resolve()));
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
