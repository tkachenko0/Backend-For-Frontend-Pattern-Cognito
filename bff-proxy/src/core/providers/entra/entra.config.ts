import { z } from 'zod';

export const entraConfigSchema = z.object({
  ENTRA_TENANT_ID: z.string().min(1, 'ENTRA_TENANT_ID is required'),
  ENTRA_CLIENT_ID: z.string().min(1, 'ENTRA_CLIENT_ID is required'),
  ENTRA_CLIENT_SECRET: z.string().min(1, 'ENTRA_CLIENT_SECRET is required'),
  ENTRA_OAUTH_SCOPES: z.string().min(1, 'ENTRA_OAUTH_SCOPES is required'),
});

export type EntraConfig = z.infer<typeof entraConfigSchema>;
