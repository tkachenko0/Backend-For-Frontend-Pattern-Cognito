import { z } from 'zod';

export const keycloakConfigSchema = z.object({
  KEYCLOAK_BASE_URL: z.string().url('KEYCLOAK_BASE_URL must be a valid URL'),
  KEYCLOAK_INTERNAL_BASE_URL: z
    .string()
    .url('KEYCLOAK_INTERNAL_BASE_URL must be a valid URL')
    .optional(),
  KEYCLOAK_REALM: z.string().min(1, 'KEYCLOAK_REALM is required'),
  KEYCLOAK_CLIENT_ID: z.string().min(1, 'KEYCLOAK_CLIENT_ID is required'),
  KEYCLOAK_CLIENT_SECRET: z
    .string()
    .min(1, 'KEYCLOAK_CLIENT_SECRET is required'),
  KEYCLOAK_OAUTH_SCOPES: z.string().min(1, 'KEYCLOAK_OAUTH_SCOPES is required'),
});

export type KeycloakConfig = z.infer<typeof keycloakConfigSchema>;
