// Starts a real FeltDB server (the Rust `feltdb-server` from rkendel1/flow_db) for integration tests.
// Set FELTDB_SERVER_BIN to its path. Without it, the tests that need one are skipped and say so.
import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';

export const FELTDB_SERVER_BIN = process.env['FELTDB_SERVER_BIN'] && existsSync(process.env['FELTDB_SERVER_BIN']) ? process.env['FELTDB_SERVER_BIN'] : undefined;

export interface FeltdbServer {
  url: string;
  /** Freezes the server process (SIGSTOP): requests hang, as in a network partition. */
  pause(): void;
  resume(): void;
  stop(): Promise<void>;
}

export async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as { port: number }).port;
      server.close(() => resolve(port));
    });
  });
}

export async function startFeltdbServer(): Promise<FeltdbServer> {
  if (!FELTDB_SERVER_BIN) throw new Error('FELTDB_SERVER_BIN is not set');
  const dir = mkdtempSync(path.join(tmpdir(), 'feltdb-server-'));
  const port = await freePort();
  const child: ChildProcess = spawn(FELTDB_SERVER_BIN, ['--port', String(port), '--data', path.join(dir, 'feltdb.log'), '--namespace', 'resolver'], {
    env: { ...process.env, FELTDB_MASTER_KEY: randomBytes(32).toString('hex'), FELTDB_ENVIRONMENT: 'development' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  // Drained, or the server blocks once a pipe buffer fills with its logs. The tail is kept for failures.
  const tail: string[] = [];
  const keep = (chunk: Buffer) => {
    tail.push(chunk.toString('utf8'));
    if (tail.length > 50) tail.shift();
  };
  child.stdout!.on('data', keep);
  child.stderr!.on('data', keep);
  const url = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 15_000;
  for (;;) {
    try {
      const response = await fetch(`${url}/revision`);
      if (response.ok) break;
    } catch {
      // not up yet
    }
    if (child.exitCode !== null) throw new Error(`feltdb-server exited with ${child.exitCode}: ${tail.join('')}`);
    if (Date.now() > deadline) throw new Error('feltdb-server did not start');
    await new Promise((r) => setTimeout(r, 100));
  }
  return {
    url,
    pause: () => child.kill('SIGSTOP'),
    resume: () => child.kill('SIGCONT'),
    async stop() {
      child.kill('SIGCONT');
      child.kill('SIGTERM');
      await new Promise((r) => (child.exitCode !== null ? r(undefined) : child.once('exit', r)));
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
