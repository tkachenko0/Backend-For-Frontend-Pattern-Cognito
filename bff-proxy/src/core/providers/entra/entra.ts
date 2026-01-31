import { AuthProvider } from '../auth.provider';
import type { TokenResponse } from '../provider.types';
import type { ConfigService } from '../../config/config';
import type { EntraConfig } from './entra.config';

export class EntraProvider extends AuthProvider {
  private readonly tokenEndpoint: string;
  private config: EntraConfig;
  private appConfig: ConfigService;

  constructor(config: EntraConfig, appConfig: ConfigService) {
    super();
    this.config = config;
    this.appConfig = appConfig;
    this.tokenEndpoint = `https://login.microsoftonline.com/${config.ENTRA_TENANT_ID}/oauth2/v2.0/token`;
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
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: this.config.ENTRA_CLIENT_ID,
        client_secret: this.config.ENTRA_CLIENT_SECRET,
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
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: this.config.ENTRA_CLIENT_ID,
        client_secret: this.config.ENTRA_CLIENT_SECRET,
        refresh_token: refreshToken,
      }),
    });

    if (!response.ok) {
      throw new Error(`Token refresh failed with status ${response.status}`);
    }

    return await response.json();
  }

  authorize(state: string, codeChallenge: string, nonce: string): string {
    const url = new URL(
      `https://login.microsoftonline.com/${this.config.ENTRA_TENANT_ID}/oauth2/v2.0/authorize`,
    );
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', this.config.ENTRA_CLIENT_ID);
    url.searchParams.set('redirect_uri', this.appConfig.get('REDIRECT_URI'));
    url.searchParams.set('scope', this.config.ENTRA_OAUTH_SCOPES);
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    url.searchParams.set('response_mode', 'query');
    return url.href;
  }

  getLogoutUrl(): string {
    const url = new URL(
      `https://login.microsoftonline.com/${this.config.ENTRA_TENANT_ID}/oauth2/v2.0/logout`,
    );
    url.searchParams.set(
      'post_logout_redirect_uri',
      this.appConfig.get('LOGOUT_REDIRECT_URI'),
    );
    return url.href;
  }

  async revokeToken(): Promise<void> {
    throw new Error('Token revocation not implemented for Microsoft Entra ID');
  }

  async getUserInfo(accessToken: string): Promise<Record<string, unknown>> {
    const response = await fetch('https://graph.microsoft.com/oidc/userinfo', {
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
    return `${this.getIssuer()}/.well-known/openid-configuration`;
  }

  getIssuer(): string {
    return `https://login.microsoftonline.com/${this.config.ENTRA_TENANT_ID}/v2.0`;
  }

  getAudience(): string {
    return this.config.ENTRA_CLIENT_ID;
  }
}
