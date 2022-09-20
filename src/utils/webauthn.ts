import { User } from '@/types';
import {
  generateRegistrationOptions,
  VerifiedRegistrationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { RegistrationCredentialJSON } from '@simplewebauthn/typescript-types';

import { ENV } from './env';
import { gqlSdk } from './gql-sdk';
import { AuthUserAuthenticators_Insert_Input } from './__generated__/graphql-request';

export const getWebAuthnRelyingParty = () =>
  ENV.AUTH_SERVER_URL && new URL(ENV.AUTH_SERVER_URL).hostname;

export const generateWebAuthnRegistrationOptions = async ({
  id,
  email,
  displayName,
}: Pick<User, 'id' | 'displayName' | 'email'>) => {
  const { authUserAuthenticators } = await gqlSdk.getUserAuthenticators({ id });

  const options = generateRegistrationOptions({
    rpID: getWebAuthnRelyingParty(),
    rpName: ENV.AUTH_WEBAUTHN_RP_NAME,
    userID: id,
    userName: displayName ?? email,
    attestationType: 'indirect',
    excludeCredentials: authUserAuthenticators.map((authenticator) => ({
      id: Buffer.from(authenticator.credentialId, 'base64url'),
      type: 'public-key',
    })),
  });

  await gqlSdk.updateUserChallenge({
    userId: id,
    challenge: options.challenge,
  });

  return options;
};

export const verifyWebAuthnRegistration = async (
  { id }: Pick<User, 'id'>,
  credential: RegistrationCredentialJSON,
  nickname?: string
) => {
  const { user } = await gqlSdk.getUserChallenge({
    id,
  });

  if (!user) {
    throw Error('user-not-found');
  }
  const { currentChallenge } = user;
  if (!currentChallenge) {
    throw Error('invalid-request');
  }

  let verification: VerifiedRegistrationResponse;
  try {
    verification = await verifyRegistrationResponse({
      credential,
      expectedChallenge: currentChallenge,
      expectedOrigin: ENV.AUTH_WEBAUTHN_RP_ORIGINS,
      expectedRPID: getWebAuthnRelyingParty(),
    });
  } catch (e) {
    throw Error('invalid-webauthn-authenticator');
  }

  const { verified, registrationInfo } = verification;

  if (!verified) {
    throw Error('invalid-webauthn-verification');
  }

  if (!registrationInfo) {
    throw Error('invalid-webauthn-verification');
  }

  const {
    credentialPublicKey,
    credentialID: credentialId,
    counter,
  } = registrationInfo;

  const newAuthenticator: AuthUserAuthenticators_Insert_Input = {
    credentialId: credentialId.toString('base64url'),
    credentialPublicKey: Buffer.from(
      '\\x' + credentialPublicKey.toString('hex')
    ).toString(),
    counter,
    nickname,
  };

  const { insertAuthUserAuthenticator } = await gqlSdk.addUserAuthenticator({
    userAuthenticator: {
      userId: id,
      ...newAuthenticator,
    },
  });

  if (!insertAuthUserAuthenticator?.id) {
    throw Error(
      'Something went wrong. Impossible to insert new authenticator in the database.'
    );
  }

  await gqlSdk.updateUser({
    id,
    user: {
      currentChallenge: null,
    },
  });
};
