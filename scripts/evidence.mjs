// 패스키 인증 증거 기록 스크립트.
// Chrome의 가상 인증기(DevTools WebAuthn)로 등록·로그인·거절을 실제 요청으로 실행하고,
// 요청과 응답을 docs/evidence/run-<날짜>.md 에 남긴다. 세션 쿠키 값은 가린다.
//
// 사용법: node scripts/evidence.mjs https://st2-six.vercel.app
// 이 스크립트는 자동 검증 계정(test-a, test-b)만 쓴다. 두 계정에 패스키가 없을 때 처음부터 돌릴 수 있다.
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
// Playwright는 package.json에 넣지 않고, 실행하는 컴퓨터에 설치된 것을 쓴다.
const { chromium } = createRequire(import.meta.url)('playwright');
import { decodeAttestationObject, decodeClientDataJSON, isoBase64URL } from '@simplewebauthn/server/helpers';

const BASE = (process.argv[2] || 'http://localhost:3000').replace(/\/$/, '');
const OUT = process.argv[3] || path.join('docs', 'evidence', `run-${new Date().toISOString().slice(0, 10)}.md`);
const lines = [];
const log = (s = '') => lines.push(s);
const mask = (s) => String(s).replace(/sid=[A-Za-z0-9_-]+/g, 'sid=****(가림)');
const short = (v) => (typeof v === 'string' && v.length > 60 ? `${v.slice(0, 24)}…(${v.length}자)` : v);
const shorten = (o) => JSON.parse(JSON.stringify(o, (k, v) => (['clientDataJSON', 'attestationObject', 'authenticatorData', 'signature', 'publicKey', 'rawId', 'userHandle'].includes(k) ? short(v) : v)));

function record(title, req, res) {
  log(`#### ${title}`);
  log('```http');
  log(mask(`${req.method} ${req.path}${req.cookie ? `\nCookie: ${req.cookie}` : ''}`));
  if (req.body !== undefined) log(`\n${JSON.stringify(shorten(req.body), null, 2)}`);
  log('```');
  log('```http');
  log(mask(`HTTP ${res.status}${res.setCookie ? `\nSet-Cookie: ${res.setCookie}` : ''}`));
  log(`\n${JSON.stringify(shorten(res.body), null, 2)}`);
  log('```');
  log();
}

// 페이지 안에서 fetch를 실행해 같은 origin·쿠키로 요청한다.
async function call(page, method, p, body) {
  const r = await page.evaluate(async ({ method, p, body }) => {
    const res = await fetch(p, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
    let data; try { data = await res.json(); } catch { data = null; }
    return { status: res.status, body: data };
  }, { method, p, body });
  return r;
}

async function callLogged(page, title, method, p, body) {
  const res = await call(page, method, p, body);
  record(title, { method, path: p, body }, res);
  return res;
}

// 브라우저에서 navigator.credentials 를 부르고 서버가 받는 JSON 모양으로 바꾼다.
const PAGE_HELPERS = () => {
  const toBuf = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), (c) => c.charCodeAt(0)).buffer;
  const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  window.__create = async (o, abort) => {
    const ac = new AbortController();
    if (abort) setTimeout(() => ac.abort(), 0);
    const c = await navigator.credentials.create({ signal: ac.signal, publicKey: { ...o, challenge: toBuf(o.challenge), user: { ...o.user, id: toBuf(o.user.id) }, excludeCredentials: (o.excludeCredentials || []).map((x) => ({ ...x, id: toBuf(x.id) })) } });
    return { id: c.id, rawId: b64(c.rawId), type: c.type, clientExtensionResults: {}, response: { clientDataJSON: b64(c.response.clientDataJSON), attestationObject: b64(c.response.attestationObject), transports: c.response.getTransports() } };
  };
  window.__get = async (o, discoverable) => {
    const c = await navigator.credentials.get({ publicKey: { ...o, challenge: toBuf(o.challenge), allowCredentials: discoverable ? [] : (o.allowCredentials || []).map((x) => ({ ...x, id: toBuf(x.id) })) } });
    return { id: c.id, rawId: b64(c.rawId), type: c.type, clientExtensionResults: {}, response: { clientDataJSON: b64(c.response.clientDataJSON), authenticatorData: b64(c.response.authenticatorData), signature: b64(c.response.signature), userHandle: c.response.userHandle ? b64(c.response.userHandle) : undefined } };
  };
};

async function newUser(browser) {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(`${BASE}/private.html`);
  await page.evaluate(PAGE_HELPERS);
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const auth = {};
  auth.add = async () => {
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
    });
    auth.id = authenticatorId;
    return authenticatorId;
  };
  auth.remove = async () => { await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: auth.id }); };
  auth.export = async () => (await cdp.send('WebAuthn.getCredentials', { authenticatorId: auth.id })).credentials;
  auth.import = async (creds) => { for (const credential of creds) await cdp.send('WebAuthn.addCredential', { authenticatorId: auth.id, credential }); };
  await auth.add();
  return { context, page, auth };
}

async function register(u, account, name, title) {
  const opt = await callLogged(u.page, `${title} — 등록 옵션 요청`, 'POST', '/api/register/options', account ? { account } : {});
  const response = await u.page.evaluate((o) => window.__create(o), opt.body);
  const verify = await callLogged(u.page, `${title} — 등록 응답 검증`, 'POST', '/api/register/verify', { name, response });
  return { opt, response, verify };
}

async function login(u, title, { account, discoverable = false, tamper = false } = {}) {
  const opt = await callLogged(u.page, `${title} — 로그인 옵션 요청`, 'POST', '/api/login/options', account ? { account } : {});
  const response = await u.page.evaluate(([o, d]) => window.__get(o, d), [opt.body, discoverable]);
  if (tamper) {
    const sig = Buffer.from(response.response.signature, 'base64url');
    sig[sig.length - 1] ^= 0x01;   // 서명 마지막 바이트 1비트를 뒤집는다
    response.response.signature = sig.toString('base64url');
  }
  const verify = await callLogged(u.page, `${title} — 서명 검증`, 'POST', '/api/login/verify', { response });
  return { opt, response, verify };
}

const sidOf = async (u) => (await u.context.cookies()).find((c) => c.name === 'sid')?.value;

async function main() {
  const browser = await chromium.launch();
  log(`# 패스키 인증 검증 기록`);
  log();
  log(`- 대상: ${BASE}`);
  log(`- 실행 시각: ${new Date().toISOString()}`);
  log(`- 인증기: Chrome DevTools 가상 인증기(ctap2, internal). 자동 검증 계정 test-a, test-b만 사용`);
  log(`- 세션 쿠키 값은 \`sid=****(가림)\` 으로 가렸다. 긴 바이너리 값은 앞 24자만 적었다.`);
  log();

  // ---------- 1. 로그인 없이 ----------
  log('## 1. 로그인 없이 비공개 영역 열기 (T08-C15~C18)');
  log();
  const anon = await newUser(browser);
  const htmlRes = await fetch(`${BASE}/private.html`);
  const html = await htmlRes.text();
  const secretTitles = ['저전력 센서 보드', '무선 충전 패드 개선', '자동 검증 A의 메모', '자동 검증 B의 메모'];
  log('#### 로그인 없이 받은 private.html 본문 검사');
  log('```text');
  log(`GET /private.html → HTTP ${htmlRes.status}, ${html.length}바이트`);
  for (const t of secretTitles) log(`"${t}" 포함 여부: ${html.includes(t) ? '있음(실패)' : '없음'}`);
  log(`<input type="password"> 개수: ${(html.match(/type="password"/g) || []).length}`);
  log('```');
  log();
  await callLogged(anon.page, '로그인 없이 비공개 자료 직접 요청', 'GET', '/api/private');
  await callLogged(anon.page, '로그인 없이 다른 계정 자료 직접 요청', 'GET', '/api/accounts/test-a/private');
  await callLogged(anon.page, '로그인 없이 패스키 목록 요청', 'GET', '/api/passkeys');
  await anon.context.close();

  // ---------- 2. 등록 ----------
  log('## 2. 패스키 등록 (T08-C19~C25)');
  log();
  const a = await newUser(browser);
  const regA1 = await register(a, 'test-a', 'A의 첫 번째 패스키', 'test-a 첫 등록');
  const att = decodeAttestationObject(isoBase64URL.toBuffer(regA1.response.response.attestationObject));
  const cd = decodeClientDataJSON(regA1.response.response.clientDataJSON);
  log('#### 등록 요청 본문을 풀어 본 결과 (개인키가 없음을 확인)');
  log('```text');
  log(`response.response 의 키: ${Object.keys(regA1.response.response).join(', ')}`);
  log(`clientDataJSON: ${JSON.stringify(cd)}`);
  log(`attestationObject 의 키: ${[...att.keys()].join(', ')} (fmt=${att.get('fmt')})`);
  log(`authData 길이: ${att.get('authData').length}바이트 — rpIdHash, flags, counter, 자격 증명 ID, COSE 공개키만 들어 있다`);
  log('요청 본문 어디에도 개인키 필드가 없다. 개인키는 인증기 안에서 만들어지고 밖으로 나오지 않는다.');
  log('```');
  log();
  await a.page.evaluate(PAGE_HELPERS);
  await login(a, 'test-a 로그인(추가 등록 전)');

  // 등록 취소
  const before = await call(a.page, 'GET', '/api/passkeys');
  const optCancel = await callLogged(a.page, '등록 취소 — 등록 옵션 요청', 'POST', '/api/register/options', {});
  const cancelErr = await a.page.evaluate(async (o) => { try { await window.__create(o, true); return 'no error'; } catch (e) { return `${e.name}: ${e.message}`; } }, optCancel.body);
  const after = await call(a.page, 'GET', '/api/passkeys');
  log('#### 등록 중간 취소');
  log('```text');
  log(`브라우저 오류: ${cancelErr}`);
  log('검증 요청(/api/register/verify)은 보내지 않았다.');
  log(`취소 전 패스키 수: ${before.body.count}, 취소 후 패스키 수: ${after.body.count}`);
  log('```');
  log();

  // 두 번째 패스키는 다른 인증기에서 만든다(excludeCredentials 때문에 같은 인증기는 거절).
  const key1 = await a.auth.export();
  await a.auth.remove();
  await a.auth.add();
  const regA2 = await register(a, null, 'A의 두 번째 패스키(보안 키 가정)', 'test-a 두 번째 등록(로그인 상태)');
  const key2 = await a.auth.export();
  log('#### 등록 챌린지 비교 (요청마다 다름)');
  log('```text');
  log(`첫 등록 챌린지   : ${regA1.opt.body.challenge}`);
  log(`취소한 등록 챌린지: ${optCancel.body.challenge}`);
  log(`두 번째 등록 챌린지: ${regA2.opt.body.challenge}`);
  log('```');
  log();

  // ---------- 3. 로그인 ----------
  log('## 3. 로그인, 서명 실패, 챌린지 재사용, 로그아웃 (T08-C27~C34)');
  log();
  const bad = await login(a, '틀린 서명으로 로그인', { tamper: true });
  const good = await login(a, '올바른 서명으로 로그인');
  const replay = await callLogged(a.page, '이미 사용한 챌린지로 같은 응답을 다시 보냄', 'POST', '/api/login/verify', { response: good.response });
  log('#### 로그인 챌린지 비교 (요청마다 다름)');
  log('```text');
  log(`틀린 서명 시도 챌린지: ${bad.opt.body.challenge}`);
  log(`성공한 로그인 챌린지 : ${good.opt.body.challenge}`);
  log('```');
  log();
  const sid = await sidOf(a);
  await callLogged(a.page, '로그아웃', 'POST', '/api/logout');
  const reuse = await fetch(`${BASE}/api/private`, { headers: { Cookie: `sid=${sid}` } });
  record('로그아웃한 뒤 예전 세션 쿠키로 다시 요청', { method: 'GET', path: '/api/private', cookie: `sid=${sid}` }, { status: reuse.status, body: await reuse.json() });

  // ---------- 4. 계정 B와 교차 접근 ----------
  log('## 4. 다른 계정의 패스키·자료 접근 (T08-C36~C41)');
  log();
  const b = await newUser(browser);
  await register(b, 'test-b', 'B의 패스키', 'test-b 첫 등록');
  await b.page.evaluate(PAGE_HELPERS);
  await login(b, 'test-b 로그인');
  const bBefore = await callLogged(b.page, 'test-b 자기 자료 건수(거절 전)', 'GET', '/api/private');

  // A 다시 로그인 (두 번째 패스키 인증기 사용 중)
  await login(a, 'test-a 다시 로그인');
  await callLogged(a.page, 'test-a 세션으로 test-b 자료 요청', 'GET', '/api/accounts/test-b/private');
  await callLogged(a.page, 'test-a 세션으로 주소에 test-b를 적어 요청 (무시되고 내 자료만 옴)', 'GET', '/api/private?account=test-b');
  await callLogged(b.page, 'test-b 세션으로 test-a 자료 요청', 'GET', '/api/accounts/test-a/private');
  const bAfter = await callLogged(b.page, 'test-b 자기 자료 건수(거절 후)', 'GET', '/api/private');
  const aKeys = await call(a.page, 'GET', '/api/passkeys');
  await callLogged(b.page, 'test-b 세션으로 test-a의 패스키 삭제 시도', 'DELETE', `/api/passkeys?id=${encodeURIComponent(aKeys.body.passkeys[0].id)}`);
  await login(b, 'test-b의 패스키로 test-a 계정 로그인 시도', { account: 'test-a', discoverable: true });
  log('#### 거절 전후 test-b 자료 건수');
  log('```text');
  log(`거절 전: ${bBefore.body.count}건, 거절 후: ${bAfter.body.count}건`);
  log('```');
  log();

  // ---------- 5. 패스키 분실 대비 ----------
  log('## 5. 패스키 두 개 중 하나 삭제 (T08-C42~C46)');
  log();
  await callLogged(a.page, 'test-a 패스키 목록 (두 개)', 'GET', '/api/passkeys');
  const firstId = regA1.verify.body.saved.credentialId;
  await callLogged(a.page, '첫 번째 패스키 삭제', 'DELETE', `/api/passkeys?id=${encodeURIComponent(firstId)}`);
  await callLogged(a.page, '삭제 후 패스키 목록 (하나)', 'GET', '/api/passkeys');
  await callLogged(a.page, '로그아웃', 'POST', '/api/logout');
  await login(a, '남은 두 번째 패스키로 로그인');
  // 지운 첫 번째 패스키가 들어 있는 인증기로 바꿔 끼운다.
  await a.auth.remove();
  await a.auth.add();
  await a.auth.import(key1);
  await login(a, '지운 첫 번째 패스키로 로그인 시도', { account: null, discoverable: true });
  await callLogged(a.page, '마지막 남은 패스키 삭제 시도', 'DELETE', `/api/passkeys?id=${encodeURIComponent(regA2.verify.body.saved.credentialId)}`);

  await browser.close();
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, lines.join('\n'));
  console.log('wrote', OUT, lines.length, 'lines');
  void key2;
}

main().catch((e) => { console.error(e); process.exit(1); });
