import type { Request, Response } from 'express';
import { logger } from '../../../core/logger/logger';
import { AuthProvider } from '../../../core/providers/auth.provider';
import { JwtService } from '../../../core/jwt/jwt.service';
import { CookieService } from '../../../core/cookies/cookie.service';
import { ConfigService } from '../../../core/config/config';
import type { Container } from '../../../core/di/container';

export function createCallbackHandler(container: Container) {
  const authProvider = container.get(AuthProvider);
  const cookieService = container.get(CookieService);
  const jwtService = container.get(JwtService);
  const configService = container.get(ConfigService);

  return async (req: Request, res: Response): Promise<void> => {
    const code = req.query['code'] as string | undefined;
    const state = req.query['state'] as string | undefined;
    const storedState = cookieService.get(req, 'oauth_state');
    const storedNonce = cookieService.get(req, 'oauth_nonce');
    const codeVerifier = cookieService.get(req, 'code_verifier');

    if (!code) {
      logger.warn('OAuth callback: No code provided');
      res.send('No code provided');
      return;
    }

    if (!state || !storedState || state !== storedState) {
      logger.warn('OAuth callback: Invalid state parameter');
      cookieService.clear(res, 'oauth_state');
      cookieService.clear(res, 'code_verifier');
      res.status(403).send('Invalid state parameter');
      return;
    }

    if (!codeVerifier) {
      logger.warn('OAuth callback: Missing code verifier');
      cookieService.clear(res, 'oauth_state');
      cookieService.clear(res, 'code_verifier');
      res.status(403).send('Missing code verifier');
      return;
    }

    cookieService.clear(res, 'oauth_state');
    cookieService.clear(res, 'oauth_nonce');
    cookieService.clear(res, 'code_verifier');

    try {
      const data = await authProvider.handShake({
        code,
        codeVerifier,
      });

      if (!data.access_token || !data.id_token) {
        logger.error('Token exchange: Missing tokens in response');
        res.status(401).send('Authentication failed');
        return;
      }

      if (!storedNonce) {
        logger.error('OAuth callback: Missing nonce cookie');
        res.status(403).send('Missing nonce');
        return;
      }

      const decodedIdToken = await jwtService.verifyToken(data.id_token);
      const decodedAccessToken = await jwtService.verifyToken(
        data.access_token,
      );

      if (!decodedIdToken['nonce'] || decodedIdToken['nonce'] !== storedNonce) {
        logger.warn('Nonce mismatch - possible replay attack');
        res.status(403).send('Invalid nonce');
        return;
      }

      if (decodedIdToken['sub'] !== decodedAccessToken['sub']) {
        logger.warn('Sub claim mismatch between ID token and access token');
        res.status(403).send('Token mismatch');
        return;
      }

      cookieService.setAuthToken(
        res,
        'id_token',
        data.id_token,
        data.expires_in,
      );
      cookieService.setAuthToken(
        res,
        'access_token',
        data.access_token,
        data.expires_in,
      );

      if (data.refresh_token) {
        cookieService.setAuthTokenWithExpiry(
          res,
          'refresh_token',
          data.refresh_token,
          jwtService.getTokenExpires(data.refresh_token),
        );
      }

      const returnTo = cookieService.get(req, 'return_to');
      if (returnTo) {
        cookieService.clear(res, 'return_to');
        res.redirect(returnTo);
      } else {
        res.redirect(configService.get('FRONTEND_REDIRECT_URL'));
      }
    } catch (err) {
      logger.error({ err }, 'Authentication error');
      res.status(500).send('Authentication error');
    }
  };
}
