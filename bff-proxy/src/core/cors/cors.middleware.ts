import cors from 'cors';

export function createCorsMiddleware(origin: string[]) {
  return cors({
    origin,
    credentials: true,
  });
}
