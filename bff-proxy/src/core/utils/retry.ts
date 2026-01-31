import { logger } from '../logger/logger';

export async function retryWithBackoff<T>(
  operation: () => Promise<T>,
  options: {
    maxRetries: number;
    initialDelayMs: number;
    operationName: string;
  },
): Promise<T> {
  const { maxRetries, initialDelayMs, operationName } = options;

  let delayMs = initialDelayMs;

  for (let i = 0; i < maxRetries; i++) {
    try {
      return await operation();
    } catch (err) {
      const isLastAttempt = i === maxRetries - 1;
      if (isLastAttempt) throw err;

      logger.warn(
        `${operationName} failed (attempt ${i + 1}/${maxRetries}), retrying in ${delayMs}ms...`,
      );
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      delayMs *= 2;
    }
  }

  throw new Error('Unreachable');
}
