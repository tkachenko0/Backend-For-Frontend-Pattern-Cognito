import jwt, { VerifyOptions } from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import { logger } from '../logger/logger';

export class JwtService {
  private client: jwksClient.JwksClient;
  private issuer: string;
  private algs: VerifyOptions['algorithms'];

  constructor(args: {
    jwksUri: string;
    issuer: string;
    cacheMs: number;
    algs: VerifyOptions['algorithms'];
  }) {
    this.issuer = args.issuer;
    this.algs = args.algs;
    this.client = jwksClient({
      jwksUri: args.jwksUri,
      cache: true,
      cacheMaxAge: args.cacheMs,
    });
  }

  verifyToken(token: string): Promise<jwt.JwtPayload> {
    return new Promise((resolve, reject) => {
      jwt.verify(
        token,
        (header: jwt.JwtHeader, callback: jwt.SigningKeyCallback) => {
          this.client.getSigningKey(header.kid, (err, key) => {
            if (err) {
              callback(err);
            } else {
              const signingKey = key?.getPublicKey();
              callback(null, signingKey);
            }
          });
        },
        {
          issuer: this.issuer,
          algorithms: this.algs,
        },
        (err, verified) => {
          if (err) {
            reject(err);
          } else if (!verified || typeof verified === 'string') {
            reject(new Error('Invalid token format'));
          } else {
            resolve(verified as jwt.JwtPayload);
          }
        },
      );
    });
  }

  async verifyTokenSafe(
    token: string | undefined,
  ): Promise<jwt.JwtPayload | null> {
    if (!token) return null;

    try {
      return await this.verifyToken(token);
    } catch (err) {
      logger.warn({ err }, 'Token verification failed');
      return null;
    }
  }

  decodeTokenSafe(token: string | undefined): jwt.JwtPayload | null {
    if (!token) return null;

    try {
      const decoded = jwt.decode(token);
      return decoded && typeof decoded !== 'string' ? decoded : null;
    } catch {
      return null;
    }
  }

  isTokenExpiringSoon(
    token: jwt.JwtPayload | null,
    thresholdInSec: number,
  ): boolean {
    if (!token) return false;

    if (!token.exp) {
      throw new Error('Token missing exp claim');
    }

    const now = Math.floor(Date.now() / 1000);
    const timeUntilExpiry = token.exp - now;

    return timeUntilExpiry < thresholdInSec;
  }

  getTokenExpires(token: string): Date {
    const decoded = jwt.decode(token);

    if (!decoded || typeof decoded === 'string') {
      throw new Error('Invalid token format');
    }

    if (!decoded.exp) {
      throw new Error('Token missing exp claim');
    }

    return new Date(decoded.exp * 1000);
  }
}
