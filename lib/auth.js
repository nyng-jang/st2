import crypto from 'node:crypto';
import { sql } from './db.js';

export const CHALLENGE_TTL_SECONDS = 300;   // 챌린지 유효 시간 5분
export const SESSION_TTL_SECONDS = 3600;    // 세션 유효 시간 1시간
const COOKIE = 'sid';

// RP ID와 origin은 요청이 들어온 호스트로 정한다. 패스키는 이 호스트에 묶인다.
export function rp(req) {
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  const isLocal = host.startsWith('localhost');
  return {
    rpID: host.split(':')[0],
    origin: `${isLocal ? 'http' : 'https'}://${host}`,
    secure: !isLocal,
  };
}

export function json(res, status, body) {
  res.status(status).setHeader('Cache-Control', 'no-store');
  res.json(body);
}

export function onlyMethod(req, res, method) {
  if (req.method !== method) {
    res.setHeader('Allow', method);
    json(res, 405, { error: 'method_not_allowed' });
    return false;
  }
  return true;
}

// 같은 사이트에서 온 요청만 상태를 바꿀 수 있게 한다(CSRF 방지 보조).
export function sameOrigin(req, res) {
  const origin = req.headers.origin;
  if (origin && origin !== rp(req).origin) {
    json(res, 403, { error: 'cross_origin_request' });
    return false;
  }
  return true;
}

const hash = (token) => crypto.createHash('sha256').update(token).digest('hex');

function readCookie(req) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === COOKIE) return v.join('=');
  }
  return null;
}

// 쿠키의 세션 토큰으로 로그인한 계정을 찾는다. 없거나 만료되면 null.
export async function currentAccount(req) {
  const token = readCookie(req);
  if (!token) return null;
  const rows = await sql`
    select account_id from sessions
    where token_hash = ${hash(token)} and expires_at > now()`;
  return rows[0]?.account_id ?? null;
}

// 로그인한 계정이 없으면 401을 보내고 null을 돌려준다.
export async function requireAccount(req, res) {
  const account = await currentAccount(req);
  if (!account) json(res, 401, { error: 'not_authenticated', message: '패스키로 로그인해야 볼 수 있어요.' });
  return account;
}

export async function startSession(req, res, accountId) {
  const token = crypto.randomBytes(32).toString('base64url');
  await sql`
    insert into sessions (token_hash, account_id, expires_at)
    values (${hash(token)}, ${accountId}, now() + ${SESSION_TTL_SECONDS} * interval '1 second')`;
  const secure = rp(req).secure ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_SECONDS}${secure}`);
}

export async function endSession(req, res) {
  const token = readCookie(req);
  if (token) await sql`delete from sessions where token_hash = ${hash(token)}`;
  const secure = rp(req).secure ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}`);
}

export async function saveChallenge({ challenge, purpose, accountId = null, viaSession = false }) {
  await sql`
    insert into challenges (challenge, purpose, account_id, via_session, expires_at)
    values (${challenge}, ${purpose}, ${accountId}, ${viaSession},
            now() + ${CHALLENGE_TTL_SECONDS} * interval '1 second')`;
}

// 응답에 담긴 챌린지를 서버 보관분에서 지우면서 꺼낸다. 한 번 꺼낸 챌린지는 다시 나오지 않는다.
export async function consumeChallenge(response, purpose) {
  let challenge;
  try {
    const clientData = JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64url').toString('utf8'));
    challenge = clientData.challenge;
  } catch {
    return null;
  }
  if (typeof challenge !== 'string') return null;
  const rows = await sql`
    delete from challenges
    where challenge = ${challenge} and purpose = ${purpose} and expires_at > now()
    returning challenge, account_id, via_session`;
  // 만료된 챌린지는 이때 함께 정리한다.
  await sql`delete from challenges where expires_at <= now()`;
  return rows[0] ?? null;
}
