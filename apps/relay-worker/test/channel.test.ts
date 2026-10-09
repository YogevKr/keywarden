import test from 'node:test';
import assert from 'node:assert/strict';
import { BrokerChannel } from '../src/index.ts';
import { encryptForPublicKey, exportPublicKey, generateEncryptionKeyPair, generateSigningKeyPair, signEnvelope } from '../../../protocol/src/index.ts';

async function fixture() {
  const values = new Map<string, any>();
  const channel = new BrokerChannel({storage:{get:async(key:string)=>values.get(key),put:async(key:string,value:unknown)=>{values.set(key,value);},delete:async(key:string)=>values.delete(key),list:async({prefix}:{prefix:string})=>new Map([...values].filter(([key])=>key.startsWith(prefix)))}});
  const signing = await generateSigningKeyPair();
  const encryption = await generateEncryptionKeyPair();
  const envelope = async (kind: Parameters<typeof signEnvelope>[0]) => signEnvelope(kind, await encryptForPublicKey('{"test":"encrypted"}', await exportPublicKey(encryption.publicKey)), signing.privateKey, await exportPublicKey(signing.publicKey));
  const call = (method: string, path: string, body?: unknown) => channel.fetch(new Request('https://relay.test'+path,{method,body:body?JSON.stringify(body):undefined}));
  return {values, envelope, call};
}

test('relay stores encrypted pairing and rejects plaintext pairing', async()=>{
  const {call,values,envelope}=await fixture();
  assert.equal((await call('POST','/pairing',{phoneId:'phone',pairingToken:'must-stay-local',signingPublicJwk:{},encryptionPublicJwk:{}})).status,400);
  assert.equal((await call('POST','/pairing',{phoneId:'phone',envelope:await envelope('phone_pairing')})).status,200);
  assert.ok(!JSON.stringify([...values]).includes('must-stay-local'));
  assert.equal((await call('GET','/pairing/phone')).status,200);
  assert.equal((await call('POST','/pairing/phone/ack')).status,200);
  assert.equal((await call('GET','/pairing/phone')).status,404);
});

test('decided requests keep encrypted status and revocation after request expiry',async()=>{
  const {call,values,envelope}=await fixture();
  const request={requestId:'request',phoneId:'phone',expiresAt:new Date(Date.now()+60000).toISOString(),envelope:await envelope('session_request'),extra:'discard-me'};
  assert.equal((await call('POST','/requests',request)).status,200);
  assert.equal((await call('POST','/requests',request)).status,409);
  assert.ok(!JSON.stringify([...values]).includes('discard-me'));
  assert.equal((await call('POST','/phones/phone/requests/request/decision',await envelope('approval_decision'))).status,200);
  assert.equal((await call('POST','/phones/phone/requests/request/decision',await envelope('approval_decision'))).status,409);
  values.get('request:request').expiresAt=new Date(Date.now()-1000).toISOString();
  assert.equal((await call('POST','/requests/request/status',await envelope('session_status'))).status,200);
  assert.equal((await call('POST','/requests/request/revocation',await envelope('session_revoke'))).status,200);
  assert.equal((await call('GET','/requests/request/status')).status,200);
  assert.deepEqual(await (await call('GET','/phones/phone/requests')).json(),{requests:[]});
});
