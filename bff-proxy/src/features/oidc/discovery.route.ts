import type { Request, Response } from 'express';
import type { Container } from '../../core/di/container';
import { AuthProvider } from '../../core/providers/auth.provider';

export function createDiscoveryHandler(container: Container) {
  const authProvider = container.get(AuthProvider);

  return async (_req: Request, res: Response): Promise<void> => {
    const config = await authProvider.getConfiguration();
    res.json(config);
  };
}
