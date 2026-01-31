import type { Request, Response } from 'express';
import { CookieService } from '../../../core/cookies/cookie.service';
import { AuthProvider } from '../../../core/providers/auth.provider';
import type { Container } from '../../../core/di/container';
import { logger } from '../../../core/logger/logger';

export function createUserInfoHandler(container: Container) {
  const authProvider = container.get(AuthProvider);
  const cookieService = container.get(CookieService);

  return async (req: Request, res: Response): Promise<void> => {
    try {
      const accessToken = cookieService.get(req, 'access_token');

      if (!accessToken) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }

      const userInfo = await authProvider.getUserInfo(accessToken);
      res.json(userInfo);
    } catch (err) {
      logger.error({ err }, 'Failed to fetch user info');
      res.status(500).json({ error: 'Failed to fetch user info' });
    }
  };
}
