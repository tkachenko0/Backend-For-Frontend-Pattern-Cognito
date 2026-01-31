import pino from 'pino';
import { pinoHttp } from 'pino-http';
import type { Request } from 'express';

const env = process.env;
const logLevel = env['LOG_LEVEL'] || 'info';

export const logger = pino({
  level: logLevel,
  transport: {
    target: 'pino-pretty',
    options: {
      colorize: true,
      translateTime: 'SYS:standard',
      ignore: 'pid,hostname',
    },
  },
  redact: {
    paths: [
      'req.headers.cookie',
      'req.headers.authorization',
      'res.headers["set-cookie"]',
      '*.token',
      '*.password',
      '*.secret',
      '*.refreshToken',
      '*.access_token',
      '*.id_token',
      '*.refresh_token',
    ],
    remove: true,
  },
});

export const httpLogger = pinoHttp({
  logger,
  autoLogging: {
    ignore: (req) => req.url === '/healthz',
  },
  customSuccessMessage: (req, res) => {
    const userSub = (req as Request).user?.sub || 'anon';
    return `${req.method} ${req.url} ${res.statusCode} [${userSub}]`;
  },
  customErrorMessage: (req, res) => {
    const userSub = (req as Request).user?.sub || 'anon';
    return `${req.method} ${req.url} ${res.statusCode} [${userSub}]`;
  },
  customAttributeKeys: {
    req: 'request',
    res: 'response',
    err: 'error',
    responseTime: 'duration',
  },
  serializers: {
    req: (req) => ({
      method: req.method,
      url: req.url,
      query: req.query,
    }),
    res: (res) => ({
      statusCode: res.statusCode,
    }),
  },
});
