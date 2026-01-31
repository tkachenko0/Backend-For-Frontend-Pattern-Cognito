import { configSchema, type AppConfig } from './config.schema';

export class ConfigService {
  private config: AppConfig;

  constructor() {
    const env = process.env;
    const result = configSchema.safeParse({
      AUTH_PROVIDER: env['AUTH_PROVIDER'],
      REDIRECT_URI: env['REDIRECT_URI'],
      LOGOUT_REDIRECT_URI: env['LOGOUT_REDIRECT_URI'],
      FRONTEND_REDIRECT_URL: env['FRONTEND_REDIRECT_URL'],
      BACKEND_URL: env['BACKEND_URL'],
      CUSTOM_CLAIMS: env['CUSTOM_CLAIMS'],
      JWKS_CACHE_MAX_AGE_MS: env['JWKS_CACHE_MAX_AGE_MS']
        ? parseInt(env['JWKS_CACHE_MAX_AGE_MS'])
        : undefined,
      JWT_ALGORITHM: env['JWT_ALGORITHM'],
      LOG_LEVEL: env['LOG_LEVEL'],
      TOKEN_REFRESH_THRESHOLD_SECONDS: env['TOKEN_REFRESH_THRESHOLD_SECONDS']
        ? parseInt(env['TOKEN_REFRESH_THRESHOLD_SECONDS'])
        : undefined,
    });

    if (!result.success) {
      console.error('Configuration validation failed:\n');
      result.error.errors.forEach((err) => {
        console.error(`${err.path.join('.')}: ${err.message}`);
      });
      process.exit(1);
    }

    this.config = result.data;
  }

  get<K extends keyof AppConfig>(key: K): AppConfig[K] {
    return this.config[key];
  }

  getAll(): AppConfig {
    return this.config;
  }
}
