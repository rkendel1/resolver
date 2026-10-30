/**
 * Structured logs: one JSON object per line, with a fixed set of fields.
 *
 * Fields are chosen by the code that logs, never copied from a request: no input, binding, secret, API key,
 * cookie or error message is ever passed here. Each record carries the instance id, so the lines of
 * several resolver instances can be told apart.
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

/** The only fields a record may carry besides `level`, `event`, `time` and `instance`. */
export interface LogFields {
  requestId?: string;
  operation?: string;
  /** A stable reason code (`resolver.*`, `sync.*`, `outbound.*`), never free text from a caller. */
  reason?: string;
  code?: string;
  error?: string;
  status?: number;
  durationMs?: number;
  tenant?: string;
  principal?: string;
  ref?: string;
  revision?: number;
  seq?: number;
  applied?: number;
  latest?: number;
  missing?: number;
  failures?: number;
  via?: string;
  origin?: string;
  count?: number;
  detail?: string;
}

export interface Logger {
  readonly instance: string;
  debug(event: string, fields?: LogFields): void;
  info(event: string, fields?: LogFields): void;
  warn(event: string, fields?: LogFields): void;
  error(event: string, fields?: LogFields): void;
}

const ALLOWED = new Set<keyof LogFields>([
  'requestId', 'operation', 'reason', 'code', 'error', 'status', 'durationMs', 'tenant', 'principal', 'ref', 'revision',
  'seq', 'applied', 'latest', 'missing', 'failures', 'via', 'origin', 'count', 'detail',
]);
const ORDER: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

export function createLogger(options: { instance: string; level?: LogLevel; write?: (line: string) => void }): Logger {
  const threshold = ORDER[options.level ?? 'info'];
  const write = options.write ?? ((line: string) => process.stdout.write(`${line}\n`));
  const emit = (level: LogLevel) => (event: string, fields: LogFields = {}) => {
    if (ORDER[level] < threshold) return;
    const record: Record<string, unknown> = { time: new Date().toISOString(), level, event, instance: options.instance };
    for (const [key, value] of Object.entries(fields)) {
      if (ALLOWED.has(key as keyof LogFields) && value !== undefined) record[key] = value;
    }
    write(JSON.stringify(record));
  };
  return { instance: options.instance, debug: emit('debug'), info: emit('info'), warn: emit('warn'), error: emit('error') };
}

/** A logger that writes nothing (the default when embedding, and in tests). */
export function silentLogger(instance = 'resolver'): Logger {
  const none = () => undefined;
  return { instance, debug: none, info: none, warn: none, error: none };
}
