import type { Response, Request } from 'express';
import { AuthCookieName, CookieName, OAuthCookieName } from './cookie.types';

export class CookieService {
  setAuthToken(
    res: Response,
    name: AuthCookieName,
    value: string,
    expiresInSeconds: number,
  ): void {
    res.cookie(name, value, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: expiresInSeconds * 1000,
    });
  }

  setAuthTokenWithExpiry(
    res: Response,
    name: AuthCookieName,
    value: string,
    expires: Date,
  ): void {
    res.cookie(name, value, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      expires,
    });
  }

  setOAuthCookie(res: Response, name: OAuthCookieName, value: string): void {
    res.cookie(name, value, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 10 * 60 * 1000,
    });
  }

  get(req: Request, name: CookieName): string | undefined {
    return req.cookies[name];
  }

  clear(res: Response, name: CookieName): void {
    res.clearCookie(name);
  }
}
