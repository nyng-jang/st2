// [등록 2단계] 인증기의 등록 응답을 검증하고 공개키만 저장한다.
import { verifyRegistrationResponse } from '@simplewebauthn/server';
import { sql } from '../../lib/db.js';
import { rp, json, onlyMethod, sameOrigin, currentAccount, consumeChallenge } from '../../lib/auth.js';

export default async function handler(req, res) {
  if (!onlyMethod(req, res, 'POST') || !sameOrigin(req, res)) return;
  const { response, name } = req.body ?? {};
  if (!response?.response?.clientDataJSON) return json(res, 400, { error: 'bad_request' });

  const stored = await consumeChallenge(response, 'register');
  if (!stored) return json(res, 400, { error: 'challenge_invalid', message: '챌린지가 없거나 이미 사용됐거나 만료됐어요.' });

  // 추가 등록이었다면 지금도 같은 계정으로 로그인해 있어야 한다.
  if (stored.via_session && (await currentAccount(req)) !== stored.account_id) {
    return json(res, 401, { error: 'not_authenticated' });
  }
  if (!stored.via_session) {
    const [{ n }] = await sql`select count(*)::int as n from credentials where account_id = ${stored.account_id}`;
    if (n > 0) return json(res, 403, { error: 'login_required' });
  }

  const { rpID, origin } = rp(req);
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: stored.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: false,
    });
  } catch (err) {
    return json(res, 400, { error: 'verification_failed', message: err.message });
  }
  if (!verification.verified) return json(res, 400, { error: 'verification_failed' });

  const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
  const label = String(name || '').trim().slice(0, 40) || `패스키 ${new Date().toISOString().slice(0, 10)}`;
  await sql`
    insert into credentials (id, account_id, public_key, counter, transports, device_type, backed_up, name)
    values (${credential.id}, ${stored.account_id}, ${Buffer.from(credential.publicKey)}, ${credential.counter},
            ${credential.transports ?? []}, ${credentialDeviceType}, ${credentialBackedUp}, ${label})`;

  json(res, 200, {
    verified: true,
    account: stored.account_id,
    saved: {
      credentialId: credential.id,
      publicKey: Buffer.from(credential.publicKey).toString('base64url'),
      name: label,
      deviceType: credentialDeviceType,
      backedUp: credentialBackedUp,
    },
  });
}
