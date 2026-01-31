import { logger } from './core/logger/logger';
import express from 'express';
import { ConfigService } from './core/config/config';
import { setupGracefulShutdown } from './core/utils/graceful-shutdown';
import { createAuthProvider } from './core/providers/provider.factory';
import { Container } from './core/di/container';
import { CookieService } from './core/cookies/cookie.service';
import { AuthProvider } from './core/providers/auth.provider';
import { JwtService } from './core/jwt/jwt.service';
import { registerMiddlewares } from './app-middlewares';
import { registerRoutes } from './app-routes';
import { errorMiddleware } from './core/error/error.middleware';

const port = 8080;

async function bootstrap() {
  const container = new Container();

  const configService = new ConfigService();
  container.register(ConfigService, configService);
  const config = configService.getAll();

  const authProvider = createAuthProvider(configService);
  container.register(AuthProvider, authProvider);

  const oidcConfig = await authProvider.getConfiguration();
  const issuer = authProvider.getIssuer();

  if (oidcConfig.issuer !== issuer) {
    throw new Error(
      `Issuer mismatch: provider=${issuer}, oidc=${oidcConfig.issuer}`,
    );
  }

  const jwtService = new JwtService({
    jwksUri: oidcConfig.jwks_uri,
    issuer,
    audience: authProvider.getAudience(),
    cacheMs: config.JWKS_CACHE_MAX_AGE_MS,
    algs: [config.JWT_ALGORITHM],
  });
  container.register(JwtService, jwtService);

  const cookieService = new CookieService();
  container.register(CookieService, cookieService);

  const app = express();

  registerMiddlewares(app, container, config.CORS_ORIGINS);

  registerRoutes(app, container, config);

  app.use(errorMiddleware);

  const server = app.listen(port, () => {
    logger.info(`Server running at port ${port}`);
    logger.info(`Auth provider: ${config.AUTH_PROVIDER}`);
    logger.info(`OAuth callback: ${config.CALLBACK_PATH}`);
    logger.info(`Logout callback: ${config.LOGOUT_CALLBACK_PATH}`);
    logger.info(`Frontend: ${config.FRONTEND_REDIRECT_URL}`);
    logger.info(`Backend: ${config.BACKEND_URL}`);
    logger.info(`CORS: ${config.CORS_ORIGINS.join(', ')}`);
    logger.info(`JWT algorithm: ${config.JWT_ALGORITHM}`);
    logger.info(`Issuer: ${issuer}`);
    logger.info(`OIDC Config: ${JSON.stringify(oidcConfig, null, 2)}`);
    logger.info(`JWKS cache: ${config.JWKS_CACHE_MAX_AGE_MS}ms`);
    logger.info(
      `Token refresh threshold: ${config.TOKEN_REFRESH_THRESHOLD_SECONDS}s`,
    );
    logger.info(`Log level: ${config.LOG_LEVEL}`);
    logger.info(`Custom claims: ${config.CUSTOM_CLAIMS.join(', ') || 'none'}`);
  });

  setupGracefulShutdown(server);
}

bootstrap().catch((err) => {
  logger.error({ err }, 'Failed to start application');
  process.exit(1);
});
