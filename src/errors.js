export class AppError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.name = 'AppError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function toAppError(err, fallbackMessage = 'Something went wrong.') {
  if (err instanceof AppError) return err;
  const message = err && typeof err.message === 'string' ? err.message : fallbackMessage;
  return new AppError(500, 'internal_error', fallbackMessage, message);
}
