import { z } from 'zod';

export const googleConfigSchema = z.object({
  GOOGLE_CLIENT_ID: z.string().min(1, 'GOOGLE_CLIENT_ID is required'),
  GOOGLE_CLIENT_SECRET: z.string().min(1, 'GOOGLE_CLIENT_SECRET is required'),
  GOOGLE_OAUTH_SCOPES: z.string().min(1, 'GOOGLE_OAUTH_SCOPES is required'),
});

export type GoogleConfig = z.infer<typeof googleConfigSchema>;
