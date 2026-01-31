import { Server } from 'http';
import { logger } from '../logger/logger';

export function setupGracefulShutdown(server: Server, timeoutMs = 10000): void {
  const shutdown = async (signal: string) => {
    logger.info(`${signal} received, shutting down gracefully`);

    server.close(() => {
      logger.info('HTTP server closed');
      process.exit(0);
    });

    setTimeout(() => {
      logger.error('Forced shutdown after timeout');
      process.exit(1);
    }, timeoutMs);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}
