import { defineConfig } from 'drizzle-kit';

const url = process.env.DATABASE_URL ?? '';

export default defineConfig({
  out: './src/migrations',
  schema: './src/schema.ts',
  dialect: 'postgresql',
  dbCredentials: { url },
  casing: 'snake_case',
  migrations: {
    // Keep migration bookkeeping in its own schema/table so it never collides
    // with the application `bit` schema.
    table: '__drizzle_migrations_bit',
    schema: 'drizzle_bit'
  }
});
