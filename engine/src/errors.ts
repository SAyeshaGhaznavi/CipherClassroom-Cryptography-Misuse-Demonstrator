/**
 * Stable error codes. The API layer maps `code` to an HTTP status and
 * returns `{ code, message }` only, never a stack trace.
 */

export type EngineErrorCode =
  | 'INVALID_INPUT'
  | 'INPUT_TOO_LARGE'
  | 'INVALID_PARAMETER'
  | 'LENGTH_MISMATCH'
  | 'UNSUPPORTED_TYPE'
  | 'FIXTURE_UNAVAILABLE'
  | 'POLICY_VIOLATION';

export interface SafeErrorResponse {
  code: EngineErrorCode;
  message: string;
}

export class EngineError extends Error {
  public readonly code: EngineErrorCode;
  public readonly httpStatus: number;

  constructor(code: EngineErrorCode, message: string, httpStatus?: number) {
    super(message);
    this.name = 'EngineError';
    this.code = code;
    if (httpStatus === undefined) {
      this.httpStatus = defaultStatusFor(code);
    } else {
      this.httpStatus = httpStatus;
    }
    Object.setPrototypeOf(this, EngineError.prototype);
  }

  /** Safe payload for the client. Contains no internal detail. */
  public toSafeResponse(): SafeErrorResponse {
    return { code: this.code, message: this.message };
  }
}

function defaultStatusFor(code: EngineErrorCode): number {
  if (code === 'INPUT_TOO_LARGE') {
    return 413;
  }
  if (code === 'UNSUPPORTED_TYPE') {
    return 422;
  }
  if (code === 'FIXTURE_UNAVAILABLE') {
    return 500;
  }
  return 400;
}

/**
 * Converts any thrown value into a safe response. Unknown errors become a
 * generic message so that internal detail never reaches the client.
 */
export function toSafeError(error: unknown): SafeErrorResponse {
  if (error instanceof EngineError) {
    return error.toSafeResponse();
  }
  return {
    code: 'INVALID_INPUT',
    message: 'The request could not be processed.'
  };
}
