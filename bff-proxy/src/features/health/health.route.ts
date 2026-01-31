import { Request, Response } from 'express';

export async function handleHealth(
  _req: Request,
  res: Response,
): Promise<void> {
  res.json({
    timestamp: Date.now(),
    uptime: process.uptime(),
  });
}
