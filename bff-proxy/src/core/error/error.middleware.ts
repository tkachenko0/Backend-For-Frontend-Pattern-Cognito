import type { Request, Response, NextFunction } from 'express';
import { logger } from '../logger/logger';

export function errorMiddleware(
  err: Error,
  req: Request,
  res: Response,
  _next: NextFunction,
) {
  logger.error({ err, url: req.url, method: req.method }, 'Unhandled error');
  if (!res.headersSent) {
    res.status(500).send('Internal server error');
  }
}
