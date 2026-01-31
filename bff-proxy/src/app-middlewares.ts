import type { Express } from 'express';
import cookieParser from 'cookie-parser';
import { Container } from './core/di/container';
import { createCorsMiddleware } from './core/cors/cors.middleware';
import { httpLogger } from './core/logger/logger';
import { createAuthMiddleware } from './features/auth/auth.middleware';

export function registerMiddlewares(
  app: Express,
  container: Container,
  corsOrigins: string[],
): void {
  app.use(createCorsMiddleware(corsOrigins));
  app.use(httpLogger);
  app.use(cookieParser());
  app.use(createAuthMiddleware(container));
}
