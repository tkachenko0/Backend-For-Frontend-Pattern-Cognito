import type { Request, Response } from 'express';
import { logger } from '../../core/logger/logger';
import type { Container } from '../../core/di/container';
import { AuthProvider } from '../../core/providers/auth.provider';

export function createJwksHandler(container: Container) {
  const authProvider = container.get(AuthProvider);

  return async (_req: Request, res: Response): Promise<void> => {
    try {
      const oidcConfig = await authProvider.getConfiguration();
      const jwksResponse = await fetch(oidcConfig.jwks_uri);

      if (!jwksResponse.ok) {
        throw new Error(`JWKS fetch failed: ${jwksResponse.status}`);
      }

      const jwks = await jwksResponse.json();
      res.json(jwks);
    } catch (err) {
      logger.error({ err }, 'Failed to fetch JWKS');
      res.status(500).json({ error: 'Failed to fetch JWKS' });
    }
  };
}
