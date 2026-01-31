import type { Request, Response } from 'express';
import type { Container } from '../../../core/di/container';

export function createAuthStatusHandler(_container: Container) {
  return (req: Request, res: Response): void => {
    if (req.user) {
      res.json({
        authenticated: true,
        user: {
          sub: req.user['sub'],
          email: req.user['email'],
        },
      });
    } else {
      res.json({
        authenticated: false,
      });
    }
  };
}
