import { sendError } from '@/errors';
import * as express from 'express';
import { ReasonPhrases } from 'http-status-codes';
import nocache from 'nocache';
import env from './env';
import { mfaRouter } from './mfa';
import { oauthProvidersRouter } from './oauth';
import { patRouter } from './pat';
import { signInRouter } from './signin';
import { signOutRouter } from './signout';
import { signUpRouter } from './signup';
import { tokenRouter } from './token';
import { userRouter } from './user';
import { verifyRouter } from './verify';

const router = express.Router();
router.use(nocache());

/**
 * GET /healthz
 * @summary Check if the server is up and running
 * @return 200 - Success - application/json
 * @tags General
 */
router.get('/healthz', (_req, res) => res.json(ReasonPhrases.OK));

/**
 * GET /version
 * @summary Get the current Hasura-auth version
 * @return {Version} 200 - Hasura auth version - application/json
 * @tags General
 */
router.get('/version', (_req, res) =>
  res.json({ version: 'v' + process.env.npm_package_version })
);

// auth routes
router.use(signUpRouter);
router.use(signInRouter);
router.use(signOutRouter);
router.use(userRouter);
router.use(mfaRouter);
router.use(tokenRouter);
router.use(patRouter);
router.use(verifyRouter);

// admin
env(router);

router.use(oauthProvidersRouter);

// all other routes should throw 404 not found
router.use('*', (rwq, res) => {
  return sendError(res, 'route-not-found');
});

export default router;
