import type { Request, Response, NextFunction } from 'express';
import { AuthProvider } from '../../core/providers/auth.provider';
import { logger } from '../../core/logger/logger';
import { JwtService } from '../../core/jwt/jwt.service';
import { CookieService } from '../../core/cookies/cookie.service';
import type { JwtPayload } from 'jsonwebtoken';
import type { Container } from '../../core/di/container';
import { ConfigService } from '../../core/config/config';

export function createAuthMiddleware(container: Container) {
  const authProvider = container.get(AuthProvider);
  const cookieService = container.get(CookieService);
  const jwtService = container.get(JwtService);
  const configService = container.get(ConfigService);

  return async (
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    const idToken = cookieService.get(req, 'id_token');
    const accessToken = cookieService.get(req, 'access_token');
    const refreshToken = cookieService.get(req, 'refresh_token');

    const verifiedIdToken = await jwtService.verifyTokenSafe(idToken, {
      skipAudience: false,
    });
    const decodedAccessToken = await jwtService.verifyTokenSafe(accessToken, {
      skipAudience: true,
    });

    if (
      verifiedIdToken &&
      decodedAccessToken &&
      verifiedIdToken['sub'] !== decodedAccessToken['sub']
    ) {
      logger.warn('Sub claim mismatch between ID token and access token');
      cookieService.clear(res, 'id_token');
      cookieService.clear(res, 'access_token');
      cookieService.clear(res, 'refresh_token');
      next();
      return;
    }

    if (!verifiedIdToken && !refreshToken) {
      next();
      return;
    }

    const shouldRefresh = shouldRefreshTokens(
      verifiedIdToken,
      decodedAccessToken,
      refreshToken,
      jwtService,
      configService.get('TOKEN_REFRESH_THRESHOLD_SECONDS'),
    );

    if (shouldRefresh) {
      await refreshTokens(
        req,
        res,
        refreshToken,
        authProvider,
        cookieService,
        jwtService,
      );
      next();
      return;
    }

    if (verifiedIdToken) {
      req.user = verifiedIdToken;
    }

    next();
  };
}

function shouldRefreshTokens(
  verifiedIdToken: JwtPayload | null,
  decodedAccessToken: JwtPayload | null,
  refreshToken: string | undefined,
  jwtService: JwtService,
  thresholdInSec: number,
): refreshToken is string {
  if (!refreshToken) return false;

  return (
    !verifiedIdToken ||
    !decodedAccessToken ||
    jwtService.isTokenExpiringSoon(verifiedIdToken, thresholdInSec) ||
    jwtService.isTokenExpiringSoon(decodedAccessToken, thresholdInSec)
  );
}

async function refreshTokens(
  req: Request,
  res: Response,
  refreshToken: string,
  authProvider: AuthProvider,
  cookieService: CookieService,
  jwtService: JwtService,
): Promise<void> {
  try {
    logger.info(`Refreshing access token`);
    const data = await authProvider.refresh({ refreshToken });

    const decodedIdToken = await jwtService.verifyToken(data.id_token, {
      skipAudience: false,
    });
    const decodedAccessToken = await jwtService.verifyToken(data.access_token, {
      skipAudience: true,
    });

    if (decodedIdToken['sub'] !== decodedAccessToken['sub']) {
      logger.warn(
        'Sub claim mismatch between ID token and access token during refresh',
      );
      return;
    }

    cookieService.setAuthToken(res, 'id_token', data.id_token, data.expires_in);
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

    req.user = decodedIdToken;
  } catch (err) {
    logger.warn({ err }, 'Token refresh failed');
    cookieService.clear(res, 'id_token');
    cookieService.clear(res, 'access_token');
    cookieService.clear(res, 'refresh_token');
  }
}
