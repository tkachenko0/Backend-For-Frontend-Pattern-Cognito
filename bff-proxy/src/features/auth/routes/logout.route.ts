import type { Request, Response } from 'express';
import { logger } from '../../../core/logger/logger';
import { CookieService } from '../../../core/cookies/cookie.service';
import { AuthProvider } from '../../../core/providers/auth.provider';
import type { Container } from '../../../core/di/container';

export function createLogoutHandler(container: Container) {
  const authProvider = container.get(AuthProvider);
  const cookieService = container.get(CookieService);

  return async (req: Request, res: Response): Promise<void> => {
    const refreshToken = cookieService.get(req, 'refresh_token');
    const userId = req.user?.sub;

    if (refreshToken) {
      try {
        await authProvider.revokeToken({ refreshToken });
        logger.info(`Token revoked successfully [${userId}]`);
      } catch (err) {
        logger.error({ err }, `Token revocation failed [${userId}]`);
      }
    } else {
      logger.info(`User logged out (no refresh token to revoke) [${userId}]`);
    }

    const logoutUrl = authProvider.getLogoutUrl();
    logger.info(`Redirecting to auth provider logout: ${logoutUrl}`);
    res.redirect(logoutUrl);
  };
}
