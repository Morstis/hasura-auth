import { ERRORS, sendError } from '@/errors';
import { logger } from '@/logger';
import { ENV, generateRedirectUrl } from '@/utils';
import {
  bodyValidator,
  queryValidator,
  redirectTo as redirectToRule,
  registrationOptions,
} from '@/validation';
import express, { Router } from 'express';
import session from 'express-session';
import grant from 'grant';
import { v4 as uuidv4 } from 'uuid';
import { OAUTH_ROUTE } from './config';
import {
  googleSignInAccessTokenSchema,
  signInWithGoogleAccessToken,
} from './native';
import { SessionStore } from './session-store';
import {
  createGrantConfig,
  createUser,
  normaliseProfile,
  preRequestProviderMiddleware,
} from './utils';

import { asyncWrapper as aw } from '@/utils';

const SESSION_NAME = 'connect.sid';

/**
 * We create a Grant configuration when the service starts,
 * so it determines which providers are enabled.
 * If a provider is enabled but incorrectly configured, the service will start,
 * but the end user will be redirected with an error to the client app.
 */
const grantConfig = createGrantConfig();

const router = Router();

router.post(
  '/native/google_token',
  bodyValidator(googleSignInAccessTokenSchema),
  aw(signInWithGoogleAccessToken)
);

/**
 * GET /signin/provider/{provider}
 * @summary
 * @param {string} provider.path.required - name param description - enum:github,google,facebook,twitter,apple,azuread,windowslive,linkedin,spotify,strava,gitlab,bitbucket,twitch
 * @param {string} redirectUrl.query.required -
 * @return {string} 302 - Redirect to the provider's authentication page
 * @tags Authentication
 */

/**
 * GET /signin/provider/{provider}/callback
 * @summary Oauth callback url, that will be used by the Oauth provider, to redirect to the client application. Attention: all providers are using a GET operation, except Apple and Azure AD that use POST
 * @param {string} provider.path.required - name param description - enum:github,google,facebook,twitter,apple,azuread,windowslive,linkedin,spotify,strava,gitlab,bitbucket,twitch
 * @param {string} redirectUrl.query.required
 * @return {string} 302 - Redirect to the initial url given as a query parameter in /signin/provider/{provider}
 * @tags Authentication
 */

router
  /**
   * Use a middleware to keep the session between Oauth requests.
   * Once the authentication choregraphy is done (either success or failure), the session is destroyed.
   */
  .use(
    session({
      secret: 'grant',
      resave: false,
      saveUninitialized: true,
      store: new SessionStore(),
      genid: () => uuidv4(),
      name: SESSION_NAME,
    })
  )

  /**
   * Grant and Oauth providers need to be able to encode/decode urls
   */
  .use(OAUTH_ROUTE, express.urlencoded({ extended: true }))

  /**
   * Determine the redirect url, and store it in the locals so it is available in next middlewares
   */
  .all(`${OAUTH_ROUTE}/:provider`, ({ query }, { locals }, next) => {
    const customRedirectUrl = redirectToRule.validate(query.redirectTo);
    if (!customRedirectUrl.error) {
      locals.redirectTo = customRedirectUrl.value;
    }
    next();
  })

  /**
   * Validate the provider configuration. Any error will be redirected to the client application:
   * 1. Check if the provider is enabled
   * 2. Check if the provider has a client id/key and secret
   *
   * The redirect url has been set in the previous middleware and is available in the locals
   */
  .all(`${OAUTH_ROUTE}/:provider`, ({ params: { provider } }, res, next) => {
    const redirectTo: string = res.locals.redirectTo;
    const providerConfig = grantConfig[provider];
    // * Check if provider is enabled
    if (!providerConfig) {
      logger.warn(`Provider "${provider}" is not enabled`);
      return sendError(res, 'disabled-endpoint', { redirectTo }, true);
    }
    // * Check if the provider has a client id and secret
    if (
      !(providerConfig.client_id && providerConfig.client_secret) &&
      !(providerConfig.key && providerConfig.secret)
    ) {
      logger.warn(`Missing client id/key or secret for provider "${provider}"`);
      return sendError(
        res,
        'invalid-oauth-configuration',
        { redirectTo },
        true
      );
    }
    next();
  })

  /**
   * Validate registration options from the query parameters
   * Don't override them with default values as we'll possible user-defined values in the callback
   */
  .all(`${OAUTH_ROUTE}/:provider`, queryValidator(registrationOptions, false))

  /**
   * Optional provider-specific middleware
   * For instance, it is possible to validate/transform additional query parameters, and to add them to the provider parameters.
   * This is what we do with WorkOS.
   * @see {@link file://./config/index.ts}
   */
  .all(`${OAUTH_ROUTE}/:provider`, preRequestProviderMiddleware)

  /**
   *  Save the initial query and the redirection url into the session to be able to retrieve them in the callback
   */
  .all(
    `${OAUTH_ROUTE}/:provider`,
    ({ session, query }, { locals: { redirectTo } }, next) => {
      session.options = query;
      session.redirectTo = redirectTo;
      return session.save(next);
    }
  )

  /**
   * Grant middleware: handle the oauth flow until the callback
   * @see {@link file://./config/index.ts}
   */
  .use(grant.express(grantConfig))

  /**
   * The following middleware is reached in the Oauth Callback:
   * 1. Destroy the Oauth session (we don't need it anymore)
   * 2. Transform the profile to a standard format
   *    @see {@link file://./config/index.ts}
   * 3. Find/create the user in the database
   * 4. Connect the user to the provider
   * 5. Generate and return a new refresh token
   */
  .all(`${OAUTH_ROUTE}/:provider/callback`, async ({ session, query }, res) => {
    const { grant, options, redirectTo = ENV.AUTH_CLIENT_URL } = { ...session };
    // * Destroy the session as it is only needed for the oauth flow
    await new Promise((resolve) => {
      session.destroy(() => {
        // * Delete the cookie that has been set by express-session manually
        // See  https://stackoverflow.com/questions/70101660/how-to-destroy-session
        res.clearCookie(SESSION_NAME);
        return resolve(null);
      });
    });

    const response = grant?.response;
    const provider = grant?.provider;

    /**
     * Send error to the client application from the query parameters
     * This function is used in several places.
     */
    const sendErrorFromQuery = (
      code?: keyof typeof ERRORS,
      fallbackMessage?: string
    ) => {
      const error =
        code ||
        (typeof query.error === 'string' ? query.error : 'invalid-request');
      const errorDescription =
        typeof query.error_description === 'string'
          ? query.error_description
          : typeof query.error === 'string' && query.error !== error
          ? query.error
          : fallbackMessage || 'Unknown error';
      const details: Record<string, string> = {
        error,
        errorDescription,
      };
      if (provider) {
        details.provider = provider;
      }
      return res.redirect(generateRedirectUrl(redirectTo, details));
    };

    if (!provider) {
      logger.warn(`No Oauth provider`);
      return sendErrorFromQuery('internal-error');
    }
    if (!response) {
      logger.warn(`No Oauth response for the provider ${provider}`);
      return sendErrorFromQuery('internal-error');
    }
    if (!response.profile) {
      logger.warn(
        `No Oauth profile in the session for the provider ${provider}`
      );
      return sendErrorFromQuery('internal-error', response.error);
    }

    const profile = await normaliseProfile(provider, response);

    const { access_token: accessToken, refresh_token: refreshToken } = response;

    if (!accessToken || !refreshToken) {
      return sendErrorFromQuery(
        undefined,
        'Grant did not get an accessToken and refreshToken'
      );
    }

    try {
      const newRefreshToken = await createUser({
        provider,
        tokens: { accessToken, refreshToken },
        profile,
        options,
      });

      return res.redirect(
        generateRedirectUrl(redirectTo, { refreshToken: newRefreshToken })
      );
    } catch (error: unknown) {
      if (error instanceof Error) {
        logger.error(error.message);
        return sendErrorFromQuery(undefined, error.message);
      }

      logger.error('unexpected Error');
      return sendErrorFromQuery(undefined, 'Unexpected Error: ' + error);
    }
  });

const oauthProvidersRouter = router;
export { oauthProvidersRouter };
