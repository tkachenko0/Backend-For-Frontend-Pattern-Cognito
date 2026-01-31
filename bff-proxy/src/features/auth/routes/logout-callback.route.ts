import type { Request, Response } from 'express';
import { ConfigService } from '../../../core/config/config';
import { logger } from '../../../core/logger/logger';
import { CookieService } from '../../../core/cookies/cookie.service';
import type { Container } from '../../../core/di/container';

export function createLogoutCallbackHandler(container: Container) {
  const cookieService = container.get(CookieService);
  const configService = container.get(ConfigService);

  return async (_req: Request, res: Response): Promise<void> => {
    logger.info('Logout callback received');

    cookieService.clear(res, 'id_token');
    cookieService.clear(res, 'access_token');
    cookieService.clear(res, 'refresh_token');

    res.redirect(configService.get('FRONTEND_REDIRECT_URL'));
  };
}
