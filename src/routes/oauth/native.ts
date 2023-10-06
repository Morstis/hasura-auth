import { RequestHandler } from 'express';
import Joi from 'joi';
import { UserData, isErrorResponse, isUserData } from './typequards';
import { NormalisedProfile, createUser } from './utils';
import { logger } from '@/logger';

const userInfoEndpoint = (accessToken: string) => {
  const baseUrl = 'https://www.googleapis.com/oauth2/v3/userinfo';
  const params = new URLSearchParams({ access_token: accessToken });
  const url = new URL(baseUrl);
  url.search = params.toString();
  return url.toString();
};
function normaliseProfile({
  sub,
  name,
  picture,
  email,
  email_verified,
  locale,
}: UserData): NormalisedProfile {
  return {
    id: sub,
    displayName: name,
    avatarUrl: picture,
    email,
    emailVerified: email_verified,
    locale: locale?.slice(0, 2),
  };
}

export const googleSignInAccessTokenSchema = Joi.object({
  access_token: Joi.string().required(),
}).meta({ className: 'SignInWithGoogleAccessToken' });

export const signInWithGoogleAccessToken: RequestHandler<
  {},
  {},
  {
    access_token: string;
  }
> = async (req, res) => {
  const {
    body: { access_token: accessToken },
  } = req;

  const googleResponse = await fetch(userInfoEndpoint(accessToken));

  const userDataOrError: unknown = await googleResponse.json();

  if (isErrorResponse(userDataOrError)) {
    return res.send(userDataOrError);
  }
  if (!isUserData(userDataOrError)) {
    return res.send({
      error: 'unknown format for google response!',
      data: userDataOrError,
    });
  }

  const profile = normaliseProfile(userDataOrError);

  try {
    const refreshToken = await createUser({
      provider: 'google',
      profile,
      tokens: {
        accessToken,
      },
    });
    return res.send({ refreshToken });
  } catch (error: unknown) {
    if (error instanceof Error) {
      logger.error(error.message);
      return res.send({ error: error.message });
    }

    logger.error('unexpected Error');
    return res.send({ error: 'Unexpected Error: ' + error });
  }
};
