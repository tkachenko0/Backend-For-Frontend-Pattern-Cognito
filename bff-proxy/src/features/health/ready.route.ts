import type { Request, Response } from 'express';
import { logger } from '../../core/logger/logger';
import type { Container } from '../../core/di/container';
import { AuthProvider } from '../../core/providers/auth.provider';

export function createReadyHandler(container: Container) {
  const authProvider = container.get(AuthProvider);

  return async (_req: Request, res: Response): Promise<void> => {
    const checks = {
      provider: false,
      jwks: false,
    };

    try {
      const discovery = await authProvider.getConfiguration();
      checks.provider = !!discovery.issuer;

      const jwksResponse = await fetch(discovery.jwks_uri);
      checks.jwks = jwksResponse.ok;

      const isReady = checks.provider && checks.jwks;

      res.status(isReady ? 200 : 503).json({
        ready: isReady,
        checks,
        timestamp: Date.now(),
      });
    } catch (err) {
      logger.error({ err }, 'Readiness check failed');
      res.status(503).json({
        ready: false,
        checks,
        timestamp: Date.now(),
      });
    }
  };
}
