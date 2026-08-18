import { IngestService, type RecordInput, RetrieverService } from '@repo/rag-core';
import { Effect } from 'effect';
import {
  buildIntegrationRuntime,
  makeAdminPool,
  makeRecordInput,
  promoteAllToActive
} from '../integration/support/harness';

/**
 * recall@k eval harness.
 *
 * Seeds a ~20-record corpus into namespace `eval`, promotes it to active, then
 * runs ~20 `(query → expected record id)` pairs through the REAL retrieval
 * pipeline (live TEI embed + rerank) and prints recall@5.
 *
 * Requires a reachable Postgres AND TEI. Run against a SCRATCH database — the
 * harness deletes and re-seeds every `namespace = 'eval'` row.
 *
 *   DATABASE_URL=postgres://... \
 *   EMBEDDING_ENDPOINT=http://localhost:8085 \
 *   RERANK_ENDPOINT=http://localhost:8086 \
 *   bun run --filter api eval:recall
 */

const K = 5;
const NAMESPACE = 'eval';

interface EvalCase {
  readonly record: Partial<RecordInput>;
  readonly query: string;
}

const CORPUS: EvalCase[] = [
  {
    record: {
      title: 'Reflected XSS',
      symptom: 'query parameters are echoed into the HTML response without output encoding',
      procedure: 'inject a script payload into the reflected parameter and confirm execution'
    },
    query: 'user input rendered into the page unescaped allows script injection'
  },
  {
    record: {
      title: 'Stored XSS in comments',
      symptom: 'persisted comment body is served back without sanitisation',
      procedure: 'store a script payload in a comment and load the page as another user'
    },
    query: 'persistent script executes for other users viewing saved content'
  },
  {
    record: {
      title: 'Error-based SQL injection',
      symptom: 'database errors leak when a single quote is supplied',
      procedure: 'inject a boolean condition into the where clause and read the error'
    },
    query: 'sql error appears after adding a quote to the input'
  },
  {
    record: {
      title: 'Blind SQL injection',
      symptom: 'no error but boolean conditions change the response',
      procedure: 'use time-based payloads to infer data one bit at a time'
    },
    query: 'infer database contents using timing differences without visible errors'
  },
  {
    record: {
      title: 'OS command injection',
      symptom: 'shell metacharacters in a parameter change command output',
      procedure: 'append a semicolon and a command to the vulnerable field'
    },
    query: 'run arbitrary shell commands through an unsanitised parameter'
  },
  {
    record: {
      title: 'IDOR on invoices',
      symptom: 'sequential resource ids expose other tenants',
      procedure: 'increment the invoice id and observe another account record'
    },
    query: 'accessing another user record by changing a numeric id'
  },
  {
    record: {
      title: 'Broken function-level authorization',
      symptom: 'a non-admin can call an admin-only endpoint',
      procedure: 'replay the admin action from a low-privileged session'
    },
    query: 'a regular user can invoke privileged administrative actions'
  },
  {
    record: {
      title: 'JWT alg none bypass',
      symptom: 'the server accepts a token with alg set to none',
      procedure: 'strip the signature and set the alg header to none, then replay'
    },
    query: 'forge an authentication token by removing its signature'
  },
  {
    record: {
      title: 'SSRF to metadata endpoint',
      symptom: 'server fetches an attacker-controlled url',
      procedure: 'point the url parameter at the cloud metadata endpoint'
    },
    query: 'make the server request an internal cloud metadata address'
  },
  {
    record: {
      title: 'Open redirect',
      symptom: 'unvalidated redirect target sends users offsite',
      procedure: 'set the next parameter to an external url'
    },
    query: 'redirect parameter forwards users to an arbitrary external site'
  },
  {
    record: {
      title: 'Path traversal file read',
      symptom: 'dot-dot-slash in a filename escapes the base directory',
      procedure: 'request ../../etc/passwd via the download endpoint'
    },
    query: 'read files outside the intended directory using directory traversal'
  },
  {
    record: {
      title: 'XXE via XML upload',
      symptom: 'external entities are resolved when parsing uploaded XML',
      procedure: 'submit a document defining an external entity to read a local file'
    },
    query: 'xml parser resolves external entities and discloses local files'
  },
  {
    record: {
      title: 'Insecure deserialization',
      symptom: 'the app deserialises untrusted objects',
      procedure: 'craft a gadget-chain payload to trigger code execution'
    },
    query: 'untrusted serialized object leads to remote code execution'
  },
  {
    record: {
      title: 'CSRF on account settings',
      symptom: 'state-changing request lacks an anti-forgery token',
      procedure: 'host a forged form that submits to the settings endpoint'
    },
    query: 'change victim settings via a forged cross-site request'
  },
  {
    record: {
      title: 'Host header password-reset poisoning',
      symptom: 'reset link is built from the request host header',
      procedure: 'set the X-Forwarded-Host header to an attacker domain and request a reset'
    },
    query: 'poison the password reset link using the host header'
  },
  {
    record: {
      title: 'Weak password reset token',
      symptom: 'reset tokens are short and predictable',
      procedure: 'enumerate candidate tokens against the reset endpoint'
    },
    query: 'guess predictable reset tokens to take over an account'
  },
  {
    record: {
      title: 'Rate-limit bypass on login',
      symptom: 'lockout is keyed on a spoofable header',
      procedure: 'rotate the X-Forwarded-For header to evade throttling'
    },
    query: 'brute force login by evading the rate limiter'
  },
  {
    record: {
      title: 'Sensitive data in error message',
      symptom: 'stack traces reveal internal paths and versions',
      procedure: 'trigger an unhandled exception and read the verbose response'
    },
    query: 'error responses leak stack traces and internal details'
  },
  {
    record: {
      title: 'GraphQL introspection exposure',
      symptom: 'introspection is enabled in production',
      procedure: 'query the schema to enumerate hidden types and fields'
    },
    query: 'enumerate the api schema through enabled graphql introspection'
  },
  {
    record: {
      title: 'CORS misconfiguration',
      symptom: 'the origin is reflected with credentials allowed',
      procedure: 'read authenticated responses from an attacker origin'
    },
    query: 'cross-origin site can read authenticated responses due to permissive cors'
  }
];

const main = async (): Promise<void> => {
  const databaseUrl = process.env.DATABASE_URL;
  const embeddingEndpoint = process.env.EMBEDDING_ENDPOINT;
  const rerankEndpoint = process.env.RERANK_ENDPOINT;

  if (!databaseUrl || !embeddingEndpoint || !rerankEndpoint) {
    console.error(
      'recall-at-k requires DATABASE_URL, EMBEDDING_ENDPOINT and RERANK_ENDPOINT. ' +
      'Point them at a scratch Postgres and running TEI servers.'
    );
    process.exit(1);
    return;
  }

  const runtime = buildIntegrationRuntime({
    databaseUrl,
    embedding: 'live',
    rerank: 'live',
    embeddingEndpoint,
    rerankEndpoint
  });
  const pool = makeAdminPool(databaseUrl);

  try {
    // Idempotent re-seed of just the eval namespace.
    await pool.query(`DELETE FROM "bit"."records" WHERE $1 = ANY(namespaces)`, [NAMESPACE]);

    const expected: Array<{ query: string; id: string }> = [];
    for (const item of CORPUS) {
      const result = await runtime.runPromise(
        Effect.flatMap(IngestService, (s) =>
          s.ingest(makeRecordInput({ namespaces: [NAMESPACE], ...item.record }))
        )
      );
      expected.push({ query: item.query, id: result.id });
    }
    await promoteAllToActive(pool);

    let hits = 0;
    for (const { query, id } of expected) {
      const { chunks } = await runtime.runPromise(
        Effect.flatMap(RetrieverService, (s) =>
          s.retrieve({ query, namespaces: [NAMESPACE], k: K })
        )
      );
      if (chunks.slice(0, K).some((c) => c.id === id)) hits += 1;
    }

    const recall = hits / expected.length;
    console.log(`recall@${K} = ${recall.toFixed(3)} (${hits}/${expected.length})`);
  } finally {
    await pool.end();
    await runtime.dispose();
  }
};

await main();
