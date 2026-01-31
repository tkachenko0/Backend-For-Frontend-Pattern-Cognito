import { AuthProvider } from './auth.provider';
import type { ConfigService } from '../config/config';
import { CognitoProvider } from './cognito/cognito';
import { cognitoConfigSchema } from './cognito/cognito.config';
import { EntraProvider } from './entra/entra';
import { entraConfigSchema } from './entra/entra.config';
import { KeycloakProvider } from './keycloak/keycloak';
import { keycloakConfigSchema } from './keycloak/keycloak.config';
import { AuthProviders } from './provider.types';

export function createAuthProvider(config: ConfigService): AuthProvider {
  const providerName = config.get('AUTH_PROVIDER');
  const env = process.env;

  switch (providerName) {
    case AuthProviders.COGNITO: {
      const cognitoConfig = cognitoConfigSchema.parse({
        COGNITO_AUTH_DOMAIN_PREFIX: env['COGNITO_AUTH_DOMAIN_PREFIX'],
        COGNITO_USER_POOL_CLIENT_ID: env['COGNITO_USER_POOL_CLIENT_ID'],
        COGNITO_USER_POOL_CLIENT_SECRET: env['COGNITO_USER_POOL_CLIENT_SECRET'],
        COGNITO_AWS_REGION: env['COGNITO_AWS_REGION'],
        COGNITO_USER_POOL_ID: env['COGNITO_USER_POOL_ID'],
        COGNITO_AWS_ENDPOINT: env['COGNITO_AWS_ENDPOINT'],
        COGNITO_OAUTH_SCOPES: env['COGNITO_OAUTH_SCOPES'],
      });
      return new CognitoProvider(cognitoConfig, config);
    }

    case AuthProviders.ENTRA: {
      const entraConfig = entraConfigSchema.parse({
        ENTRA_TENANT_ID: env['ENTRA_TENANT_ID'],
        ENTRA_CLIENT_ID: env['ENTRA_CLIENT_ID'],
        ENTRA_CLIENT_SECRET: env['ENTRA_CLIENT_SECRET'],
        ENTRA_OAUTH_SCOPES: env['ENTRA_OAUTH_SCOPES'],
      });
      return new EntraProvider(entraConfig, config);
    }

    case AuthProviders.KEYCLOAK: {
      const keycloakConfig = keycloakConfigSchema.parse({
        KEYCLOAK_BASE_URL: env['KEYCLOAK_BASE_URL'],
        KEYCLOAK_INTERNAL_BASE_URL: env['KEYCLOAK_INTERNAL_BASE_URL'],
        KEYCLOAK_REALM: env['KEYCLOAK_REALM'],
        KEYCLOAK_CLIENT_ID: env['KEYCLOAK_CLIENT_ID'],
        KEYCLOAK_CLIENT_SECRET: env['KEYCLOAK_CLIENT_SECRET'],
        KEYCLOAK_OAUTH_SCOPES: env['KEYCLOAK_OAUTH_SCOPES'],
      });
      return new KeycloakProvider(keycloakConfig, config);
    }

    default:
      throw new Error(`Unknown auth provider: ${providerName}`);
  }
}
