import { z } from 'zod';
import { AuthProviders } from '../providers/provider.types';

export const configSchema = z
  .object({
    REDIRECT_URI: z.string().url('REDIRECT_URI must be a valid URL'),
    LOGOUT_REDIRECT_URI: z
      .string()
      .url('LOGOUT_REDIRECT_URI must be a valid URL'),
    FRONTEND_REDIRECT_URL: z
      .string()
      .url('FRONTEND_REDIRECT_URL must be a valid URL'),
    BACKEND_URL: z.string().url('BACKEND_URL must be a valid URL'),
    CUSTOM_CLAIMS: z
      .string()
      .default('')
      .transform((val) => (val ? val.split(',').map((s) => s.trim()) : [])),

    JWKS_CACHE_MAX_AGE_MS: z
      .number()
      .positive('JWKS_CACHE_MAX_AGE_MS must be positive'),
    JWT_ALGORITHM: z.enum([
      'RS256',
      'RS384',
      'RS512',
      'ES256',
      'ES384',
      'ES512',
    ]),
    LOG_LEVEL: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']),
    TOKEN_REFRESH_THRESHOLD_SECONDS: z.number().positive(),
    AUTH_PROVIDER: z.enum([
      AuthProviders.COGNITO,
      AuthProviders.ENTRA,
      AuthProviders.KEYCLOAK,
    ]),
  })
  .transform((data) => {
    const loginCallbackPath = new URL(data.REDIRECT_URI).pathname;
    const logoutCallbackPath = new URL(data.LOGOUT_REDIRECT_URI).pathname;

    if (loginCallbackPath === logoutCallbackPath) {
      throw new Error(
        'REDIRECT_URI and LOGOUT_REDIRECT_URI must have different paths',
      );
    }

    const frontendOrigin = new URL(data.FRONTEND_REDIRECT_URL).origin;

    return {
      ...data,
      CALLBACK_PATH: loginCallbackPath,
      LOGOUT_CALLBACK_PATH: logoutCallbackPath,
      CORS_ORIGINS: [frontendOrigin],
    };
  });

export type AppConfig = z.infer<typeof configSchema>;
