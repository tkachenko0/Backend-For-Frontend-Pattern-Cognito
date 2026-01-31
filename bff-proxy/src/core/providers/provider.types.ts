export const AuthProviders = {
  COGNITO: 'cognito',
  ENTRA: 'entra',
  KEYCLOAK: 'keycloak',
} as const;

export type AuthProviderType =
  (typeof AuthProviders)[keyof typeof AuthProviders];

export type TokenResponse = {
  id_token: string;
  access_token: string;
  refresh_token?: string;
  expires_in: number;
};

export interface OpenIDConfiguration {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri: string;
  revocation_endpoint?: string;
  response_types_supported: string[];
  grant_types_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
  id_token_signing_alg_values_supported: string[];
  scopes_supported?: string[];
  claims_supported?: string[];
}
