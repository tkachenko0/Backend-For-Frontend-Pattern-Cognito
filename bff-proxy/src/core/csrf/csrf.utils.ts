import crypto from 'crypto';
import type { Response } from 'express';
import { CookieService } from '../cookies/cookie.service';

export function setCsrfToken(
  res: Response,
  cookieService: CookieService,
  expiresInSeconds: number,
): void {
  const token = crypto.randomBytes(32).toString('hex');
  cookieService.setCsrfCookie(res, 'csrf_token', token, expiresInSeconds);
}
