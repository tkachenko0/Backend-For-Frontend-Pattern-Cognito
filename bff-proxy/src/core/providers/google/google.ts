import { AuthProvider } from '../auth.provider';
import type { TokenResponse } from '../provider.types';
import type { GoogleConfig } from './google.config';
import type { ConfigService } from '../../config/config';

export class GoogleProvider extends AuthProvider {
  private readonly tokenEndpoint =
    'https://oauth2.googleapis.com/token';
  private readonly revocationEndpoint =
    'https://oauth2.googleapis.com/revoke';
  private readonly userInfoEndpoint =
    'https://openidconnect.googleapis.com/v1/userinfo';
  private config: GoogleConfig;
  private appConfig: ConfigService;

  constructor(config: GoogleConfig, appConfig: ConfigService) {
    super();
    this.config = config;
    this.appConfig = appConfig;
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
        client_id: this.config.GOOGLE_CLIENT_ID,
        client_secret: this.config.GOOGLE_CLIENT_SECRET,
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
        client_id: this.config.GOOGLE_CLIENT_ID,
        client_secret: this.config.GOOGLE_CLIENT_SECRET,
        refresh_token: refreshToken,
      }),
    });

    if (!response.ok) {
      throw new Error(`Token refresh failed with status ${response.status}`);
    }

    return await response.json();
  }

  authorize(state: string, codeChallenge: string, nonce: string): string {
    const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', this.config.GOOGLE_CLIENT_ID);
    url.searchParams.set('redirect_uri', this.appConfig.get('REDIRECT_URI'));
    url.searchParams.set('scope', this.config.GOOGLE_OAUTH_SCOPES);
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    url.searchParams.set('access_type', 'offline');
    url.searchParams.set('prompt', 'consent');
    return url.href;
  }

  getLogoutUrl(): string {
    return this.appConfig.get('FRONTEND_REDIRECT_URL');
  }

  async revokeToken({ refreshToken }: { refreshToken: string }): Promise<void> {
    const response = await fetch(this.revocationEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        token: refreshToken,
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
    return 'https://accounts.google.com/.well-known/openid-configuration';
  }

  getIssuer(): string {
    return 'https://accounts.google.com';
  }

  getAudience(): string {
    return this.config.GOOGLE_CLIENT_ID;
  }
}
