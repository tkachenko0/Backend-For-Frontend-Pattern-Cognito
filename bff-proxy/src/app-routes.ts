import type { Express } from 'express';
import type { Container } from './core/di/container';
import type { AppConfig } from './core/config/config.schema';
import { createCallbackHandler } from './features/auth/routes/login-callback.route';
import { createLoginHandler } from './features/auth/routes/login.route';
import { createLogoutHandler } from './features/auth/routes/logout.route';
import { createLogoutCallbackHandler } from './features/auth/routes/logout-callback.route';
import { createUserInfoHandler } from './features/auth/routes/userinfo.route';
import { createAuthStatusHandler } from './features/auth/routes/auth-status.route';
import { handleHealth } from './features/health/health.route';
import { createReadyHandler } from './features/health/ready.route';
import { createDiscoveryHandler } from './features/oidc/discovery.route';
import { createJwksHandler } from './features/oidc/jwks.route';
import { createApiProxy } from './features/api-proxy/proxy.middleware';

export function registerRoutes(
  app: Express,
  container: Container,
  config: AppConfig,
): void {
  app.get('/', (_req, res) => {
    res.send('BFF Proxy');
  });
  app.get(config.CALLBACK_PATH, createCallbackHandler(container));
  app.get(config.LOGOUT_CALLBACK_PATH, createLogoutCallbackHandler(container));
  app.get('/auth/login', createLoginHandler(container));
  app.get('/auth/logout', createLogoutHandler(container));
  app.get('/auth/status', createAuthStatusHandler(container));
  app.get('/auth/userinfo', createUserInfoHandler(container));
  app.get(
    '/.well-known/openid-configuration',
    createDiscoveryHandler(container),
  );
  app.get('/.well-known/jwks.json', createJwksHandler(container));
  app.get('/healthz', handleHealth);
  app.get('/readyz', createReadyHandler(container));
  app.use('/api', createApiProxy(config.BACKEND_URL, config.CUSTOM_CLAIMS));
}
