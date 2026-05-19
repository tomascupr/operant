import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";

export type JsonStubHandler = (
  req: IncomingMessage,
  body: unknown,
) => { status: number; body?: unknown; contentType?: string; rawBody?: string };

export async function withJsonStub(handler: JsonStubHandler, run: (baseUrl: string) => Promise<void>): Promise<void> {
  const server: Server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    const raw = Buffer.concat(chunks).toString("utf8");
    const parsed = raw ? JSON.parse(raw) : undefined;
    const response = handler(req, parsed);
    res.writeHead(response.status, { "content-type": response.contentType ?? "application/json" });
    if (response.rawBody !== undefined) res.end(response.rawBody);
    else res.end(response.body === undefined ? "" : JSON.stringify(response.body));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address() as AddressInfo;
    await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}
