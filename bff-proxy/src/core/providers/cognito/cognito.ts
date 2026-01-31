import { AuthProvider } from '../auth.provider';
import type { TokenResponse } from '../provider.types';
import type { ConfigService } from '../../config/config';
import type { CognitoConfig } from './cognito.config';

export class CognitoProvider extends AuthProvider {
  private readonly tokenEndpoint: string;
  private readonly revocationEndpoint: string;
  private readonly userInfoEndpoint: string;
  private readonly authHeader: string;
  private config: CognitoConfig;
  private appConfig: ConfigService;

  constructor(config: CognitoConfig, appConfig: ConfigService) {
    super();
    this.config = config;
    this.appConfig = appConfig;
    this.tokenEndpoint = `https://${config.COGNITO_AUTH_DOMAIN_PREFIX}.auth.${config.COGNITO_AWS_REGION}.amazoncognito.com/oauth2/token`;
    this.revocationEndpoint = `https://${config.COGNITO_AUTH_DOMAIN_PREFIX}.auth.${config.COGNITO_AWS_REGION}.amazoncognito.com/oauth2/revoke`;
    this.userInfoEndpoint = `https://${config.COGNITO_AUTH_DOMAIN_PREFIX}.auth.${config.COGNITO_AWS_REGION}.amazoncognito.com/oauth2/userInfo`;
    this.authHeader = Buffer.from(
      `${config.COGNITO_USER_POOL_CLIENT_ID}:${config.COGNITO_USER_POOL_CLIENT_SECRET}`,
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
        client_id: this.config.COGNITO_USER_POOL_CLIENT_ID,
        client_secret: this.config.COGNITO_USER_POOL_CLIENT_SECRET,
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
        client_id: this.config.COGNITO_USER_POOL_CLIENT_ID,
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
      `https://${this.config.COGNITO_AUTH_DOMAIN_PREFIX}.auth.${this.config.COGNITO_AWS_REGION}.amazoncognito.com/oauth2/authorize`,
    );
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', this.config.COGNITO_USER_POOL_CLIENT_ID);
    url.searchParams.set('redirect_uri', this.appConfig.get('REDIRECT_URI'));
    url.searchParams.set('scope', this.config.COGNITO_OAUTH_SCOPES);
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    return url.href;
  }

  getLogoutUrl(): string {
    const url = new URL(
      `https://${this.config.COGNITO_AUTH_DOMAIN_PREFIX}.auth.${this.config.COGNITO_AWS_REGION}.amazoncognito.com/logout`,
    );
    url.searchParams.set('client_id', this.config.COGNITO_USER_POOL_CLIENT_ID);
    url.searchParams.set(
      'logout_uri',
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
        client_id: this.config.COGNITO_USER_POOL_CLIENT_ID,
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
    return `${this.getIssuer()}/.well-known/openid-configuration`;
  }

  getIssuer(): string {
    return `${this.config.COGNITO_AWS_ENDPOINT}/${this.config.COGNITO_USER_POOL_ID}`;
  }

  getAudience(): string {
    return this.config.COGNITO_USER_POOL_CLIENT_ID;
  }
}
