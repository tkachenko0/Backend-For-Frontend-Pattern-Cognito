import { z } from 'zod';

export const cognitoConfigSchema = z.object({
  COGNITO_AUTH_DOMAIN_PREFIX: z
    .string()
    .min(1, 'COGNITO_AUTH_DOMAIN_PREFIX is required'),
  COGNITO_USER_POOL_CLIENT_ID: z
    .string()
    .min(1, 'COGNITO_USER_POOL_CLIENT_ID is required'),
  COGNITO_USER_POOL_CLIENT_SECRET: z
    .string()
    .min(1, 'COGNITO_USER_POOL_CLIENT_SECRET is required'),
  COGNITO_AWS_REGION: z.string().min(1, 'COGNITO_AWS_REGION is required'),
  COGNITO_USER_POOL_ID: z.string().min(1, 'COGNITO_USER_POOL_ID is required'),
  COGNITO_AWS_ENDPOINT: z
    .string()
    .url('COGNITO_AWS_ENDPOINT must be a valid URL'),
  COGNITO_OAUTH_SCOPES: z.string().min(1, 'COGNITO_OAUTH_SCOPES is required'),
});

export type CognitoConfig = z.infer<typeof cognitoConfigSchema>;
