import { AuthProvider } from '../auth.provider';
import type { TokenResponse } from '../provider.types';
import type { ConfigService } from '../../config/config';
import type { KeycloakConfig } from './keycloak.config';

export class KeycloakProvider extends AuthProvider {
  private readonly tokenEndpoint: string;
  private readonly revocationEndpoint: string;
  private readonly userInfoEndpoint: string;
  private readonly authHeader: string;
  private readonly internalBaseUrl: string;
  private config: KeycloakConfig;
  private appConfig: ConfigService;

  constructor(config: KeycloakConfig, appConfig: ConfigService) {
    super();
    this.config = config;
    this.appConfig = appConfig;
    this.internalBaseUrl =
      config.KEYCLOAK_INTERNAL_BASE_URL || config.KEYCLOAK_BASE_URL;

    const baseUrl = `${this.internalBaseUrl}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect`;
    this.tokenEndpoint = `${baseUrl}/token`;
    this.revocationEndpoint = `${baseUrl}/revoke`;
    this.userInfoEndpoint = `${baseUrl}/userinfo`;
    this.authHeader = Buffer.from(
      `${this.config.KEYCLOAK_CLIENT_ID}:${this.config.KEYCLOAK_CLIENT_SECRET}`,
    ).toString('base64');
  }

  async handShake({
    code,
    codeVerifier,
  }: {
    code: string;
    codeVerifier: string;
  }): Promise<TokenResponse> {
    const response = await fetch(this.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${this.authHeader}`,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: this.config.KEYCLOAK_CLIENT_ID,
        client_secret: this.config.KEYCLOAK_CLIENT_SECRET,
        redirect_uri: this.appConfig.get('REDIRECT_URI'),
        code,
        code_verifier: codeVerifier,
      }),
    });

    if (!response.ok) {
      throw new Error(`Token exchange failed with status ${response.status}`);
    }

    return await response.json();
  }

  async refresh({
    refreshToken,
  }: {
    refreshToken: string;
  }): Promise<TokenResponse> {
    const response = await fetch(this.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${this.authHeader}`,
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
      }),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(
        `Token refresh failed with status ${response.status}: ${errorBody}`,
      );
    }

    return await response.json();
  }

  authorize(state: string, codeChallenge: string, nonce: string): string {
    const url = new URL(
      `${this.config.KEYCLOAK_BASE_URL}/realms/${this.config.KEYCLOAK_REALM}/protocol/openid-connect/auth`,
    );
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', this.config.KEYCLOAK_CLIENT_ID);
    url.searchParams.set('redirect_uri', this.appConfig.get('REDIRECT_URI'));
    url.searchParams.set('scope', this.config.KEYCLOAK_OAUTH_SCOPES);
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    return url.href;
  }

  getLogoutUrl(): string {
    const url = new URL(
      `${this.config.KEYCLOAK_BASE_URL}/realms/${this.config.KEYCLOAK_REALM}/protocol/openid-connect/logout`,
    );
    url.searchParams.set('client_id', this.config.KEYCLOAK_CLIENT_ID);
    url.searchParams.set(
      'post_logout_redirect_uri',
      this.appConfig.get('LOGOUT_REDIRECT_URI'),
    );
    return url.href;
  }

  async revokeToken({ refreshToken }: { refreshToken: string }): Promise<void> {
    const response = await fetch(this.revocationEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${this.authHeader}`,
      },
      body: new URLSearchParams({
        token: refreshToken,
        client_id: this.config.KEYCLOAK_CLIENT_ID,
      }),
    });

    if (!response.ok) {
      throw new Error(`Token revocation failed with status ${response.status}`);
    }
  }

  async getUserInfo(accessToken: string): Promise<Record<string, unknown>> {
    const response = await fetch(this.userInfoEndpoint, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error(`UserInfo request failed with status ${response.status}`);
    }

    return await response.json();
  }

  getOpenIDConfigurationRoute(): string {
    return `${this.internalBaseUrl}/realms/${this.config.KEYCLOAK_REALM}/.well-known/openid-configuration`;
  }

  getIssuer(): string {
    return `${this.config.KEYCLOAK_BASE_URL}/realms/${this.config.KEYCLOAK_REALM}`;
  }
}
