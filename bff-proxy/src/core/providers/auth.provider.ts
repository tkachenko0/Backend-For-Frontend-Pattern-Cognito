import type { OpenIDConfiguration, TokenResponse } from './provider.types';
import { retryWithBackoff } from '../utils/retry';

export abstract class AuthProvider {
  private oidcConfig: OpenIDConfiguration | null = null;

  async getConfiguration(): Promise<OpenIDConfiguration> {
    if (this.oidcConfig) {
      return this.oidcConfig;
    }
    this.oidcConfig = await retryWithBackoff(() => this.getOIDC(), {
      maxRetries: 10,
      initialDelayMs: 1000,
      operationName: 'Fetch OIDC configuration',
    });
    return this.oidcConfig;
  }

  async getJwksUri(): Promise<string> {
    const oidcConfig = await this.getConfiguration();
    return oidcConfig.jwks_uri;
  }

  abstract handShake(params: {
    code: string;
    codeVerifier: string;
  }): Promise<TokenResponse>;

  abstract refresh(params: { refreshToken: string }): Promise<TokenResponse>;

  abstract authorize(
    state: string,
    codeChallenge: string,
    nonce: string,
  ): string;

  abstract getLogoutUrl(): string;

  abstract getUserInfo(accessToken: string): Promise<Record<string, unknown>>;

  abstract getOpenIDConfigurationRoute(): string;

  abstract getIssuer(): string;

  private async getOIDC(): Promise<OpenIDConfiguration> {
    const discoveryUrl = this.getOpenIDConfigurationRoute();

    const response = await fetch(discoveryUrl);

    if (!response.ok) {
      throw new Error(
        `Failed to fetch OpenID configuration: ${response.status}`,
      );
    }

    return await response.json();
  }

  abstract revokeToken(params: { refreshToken: string }): Promise<void>;
}
