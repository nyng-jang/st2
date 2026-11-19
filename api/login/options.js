// [로그인 1단계] 로그인할 때마다 새 일회용 챌린지를 만들어 보관하고 보낸다.
import { generateAuthenticationOptions } from '@simplewebauthn/server';
import { sql } from '../../lib/db.js';
import { rp, json, onlyMethod, sameOrigin, saveChallenge } from '../../lib/auth.js';

export default async function handler(req, res) {
  if (!onlyMethod(req, res, 'POST') || !sameOrigin(req, res)) return;

  // 계정을 적으면 그 계정의 패스키로만 통과하도록 챌린지에 계정을 묶는다.
  // 계정을 비우면 인증기가 고른 패스키의 주인 계정으로 로그인한다.
  const accountId = req.body?.account ? String(req.body.account) : null;
  let allowCredentials = [];
  if (accountId) {
    const [account] = await sql`select id from accounts where id = ${accountId}`;
    if (!account) return json(res, 404, { error: 'unknown_account' });
    const creds = await sql`select id, transports from credentials where account_id = ${accountId}`;
    allowCredentials = creds.map((c) => ({ id: c.id, transports: c.transports }));
  }

  const options = await generateAuthenticationOptions({
    rpID: rp(req).rpID,
    allowCredentials,
    userVerification: 'preferred',
  });
  await saveChallenge({ challenge: options.challenge, purpose: 'login', accountId });
  json(res, 200, options);
}
