export type AuthCookieName = 'id_token' | 'access_token' | 'refresh_token';

export type OAuthCookieName =
  | 'oauth_state'
  | 'oauth_nonce'
  | 'code_verifier'
  | 'return_to';

export type CsrfCookieName = 'csrf_token';

export type CookieName = AuthCookieName | OAuthCookieName | CsrfCookieName;
