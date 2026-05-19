import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

const { Pool } = pg;

export type Database = pg.Pool;

export function createPool(connectionString = process.env.DATABASE_URL): Database {
  if (!connectionString) throw new Error("DATABASE_URL is required");
  return new Pool({ connectionString });
}

export async function runMigrations(pool: Database): Promise<void> {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../migrations");
  const files = (await readdir(root)).filter((file) => file.endsWith(".sql")).sort();
  await pool.query("CREATE TABLE IF NOT EXISTS schema_migrations (id text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())");
  for (const file of files) {
    const sql = await readFile(path.join(root, file), "utf8");
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const existing = await client.query("SELECT 1 FROM schema_migrations WHERE id = $1", [file]);
      if (existing.rowCount) {
        await client.query("COMMIT");
        continue;
      }
      await client.query(sql);
      await client.query("INSERT INTO schema_migrations (id) VALUES ($1)", [file]);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }
}
