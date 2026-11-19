// [등록 1단계] 등록용 일회용 챌린지를 만들어 서버에 보관하고 옵션을 보낸다.
import { generateRegistrationOptions } from '@simplewebauthn/server';
import { sql } from '../../lib/db.js';
import { rp, json, onlyMethod, sameOrigin, currentAccount, saveChallenge } from '../../lib/auth.js';

export default async function handler(req, res) {
  if (!onlyMethod(req, res, 'POST') || !sameOrigin(req, res)) return;

  // 로그인한 상태면 본문의 계정은 무시하고 내 계정에 패스키를 추가한다.
  const sessionAccount = await currentAccount(req);
  const accountId = sessionAccount ?? String(req.body?.account ?? '');

  const [account] = await sql`select id, display_name from accounts where id = ${accountId}`;
  if (!account) return json(res, 404, { error: 'unknown_account', message: '미리 만들어 둔 가상 계정만 쓸 수 있어요.' });

  const existing = await sql`select id, transports from credentials where account_id = ${accountId}`;
  // 패스키가 이미 있는 계정에 새 패스키를 더하려면 그 계정으로 먼저 로그인해야 한다.
  if (!sessionAccount && existing.length > 0) {
    return json(res, 403, { error: 'login_required', message: '이미 패스키가 있는 계정이에요. 로그인한 뒤 추가할 수 있어요.' });
  }

  const { rpID } = rp(req);
  const options = await generateRegistrationOptions({
    rpName: '장나영 포트폴리오 비공개 영역',
    rpID,
    userName: account.id,
    userDisplayName: account.display_name,
    userID: new TextEncoder().encode(account.id),
    attestationType: 'none',
    excludeCredentials: existing.map((c) => ({ id: c.id, transports: c.transports })),
    authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
  });

  await saveChallenge({ challenge: options.challenge, purpose: 'register', accountId, viaSession: !!sessionAccount });
  json(res, 200, options);
}
