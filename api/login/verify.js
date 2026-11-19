// [로그인 2단계] 저장해 둔 공개키로 서명을 검증한 뒤에만 세션을 만든다.
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { sql } from '../../lib/db.js';
import { rp, json, onlyMethod, sameOrigin, consumeChallenge, startSession } from '../../lib/auth.js';

export default async function handler(req, res) {
  if (!onlyMethod(req, res, 'POST') || !sameOrigin(req, res)) return;
  const { response } = req.body ?? {};
  if (!response?.id || !response?.response?.clientDataJSON) return json(res, 400, { error: 'bad_request' });

  // 챌린지는 검증 전에 먼저 지운다. 같은 응답을 다시 보내면 여기서 막힌다.
  const stored = await consumeChallenge(response, 'login');
  if (!stored) return json(res, 400, { error: 'challenge_invalid', message: '챌린지가 없거나 이미 사용됐거나 만료됐어요.' });

  const [cred] = await sql`select * from credentials where id = ${response.id}`;
  if (!cred) return json(res, 401, { error: 'unknown_credential', message: '등록되지 않았거나 삭제된 패스키예요.' });
  if (stored.account_id && stored.account_id !== cred.account_id) {
    return json(res, 401, { error: 'credential_account_mismatch', message: '이 계정의 패스키가 아니에요.' });
  }

  const { rpID, origin } = rp(req);
  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: stored.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: cred.id,
        publicKey: new Uint8Array(cred.public_key),
        counter: Number(cred.counter),
        transports: cred.transports,
      },
      requireUserVerification: false,
    });
  } catch (err) {
    return json(res, 401, { error: 'signature_invalid', message: err.message });
  }
  if (!verification.verified) return json(res, 401, { error: 'signature_invalid' });

  await sql`
    update credentials set counter = ${verification.authenticationInfo.newCounter}, last_used_at = now()
    where id = ${cred.id}`;
  await startSession(req, res, cred.account_id);
  json(res, 200, { verified: true, account: cred.account_id, credentialName: cred.name });
}
