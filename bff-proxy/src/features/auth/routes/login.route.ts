import type { Request, Response } from 'express';
import crypto from 'crypto';
import type { Container } from '../../../core/di/container';
import { AuthProvider } from '../../../core/providers/auth.provider';
import { CookieService } from '../../../core/cookies/cookie.service';
import { logger } from '../../../core/logger/logger';

export function createLoginHandler(container: Container) {
  const authProvider = container.get(AuthProvider);
  const cookieService = container.get(CookieService);

  return (req: Request, res: Response): void => {
    try {
      const returnTo = req.query['returnTo'];

      const state = crypto
        .randomBytes(32)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

      const nonce = crypto
        .randomBytes(32)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

      const codeVerifier = crypto
        .randomBytes(32)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

      const codeChallenge = crypto
        .createHash('sha256')
        .update(codeVerifier)
        .digest('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

      cookieService.setOAuthCookie(res, 'oauth_state', state);
      cookieService.setOAuthCookie(res, 'oauth_nonce', nonce);
      cookieService.setOAuthCookie(res, 'code_verifier', codeVerifier);

      if (returnTo) {
        cookieService.setOAuthCookie(res, 'return_to', returnTo as string);
      }

      const loginUrl = authProvider.authorize(state, codeChallenge, nonce);
      res.redirect(loginUrl);
    } catch (err) {
      logger.error({ err }, 'Login failed');
      res.status(500).json({ error: 'Login failed' });
    }
  };
}
