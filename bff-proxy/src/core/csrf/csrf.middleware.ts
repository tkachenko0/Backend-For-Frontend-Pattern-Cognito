import type { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { CookieService } from '../cookies/cookie.service';
import type { Container } from '../di/container';
import { logger } from '../logger/logger';

const AUTH_COOKIE_NAMES = ['id_token', 'access_token', 'refresh_token'] as const;

function isAuthenticated(req: Request, cookieService: CookieService): boolean {
  return AUTH_COOKIE_NAMES.some((name) => cookieService.get(req, name));
}

export function createCsrfMiddleware(container: Container) {
  const cookieService = container.get(CookieService);

  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.path.startsWith('/api')) {
      next();
      return;
    }

    if (!isAuthenticated(req, cookieService)) {
      next();
      return;
    }

    const cookieToken = cookieService.get(req, 'csrf_token');
    const headerToken = req.headers['x-csrf-token'] as string | undefined;

    if (
      !cookieToken ||
      !headerToken ||
      !crypto.timingSafeEqual(
        Buffer.from(cookieToken),
        Buffer.from(headerToken),
      )
    ) {
      logger.warn('CSRF token validation failed');
      res.status(403).json({ error: 'CSRF token validation failed' });
      return;
    }

    next();
  };
}
