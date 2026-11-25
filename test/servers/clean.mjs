// A well-behaved MCP server for --probe tests: two plain tools.
import { createInterface } from "node:readline";
const tools = [
  { name: "get_weather", description: "Returns the forecast for a city.", inputSchema: { type: "object", properties: { city: { type: "string" } } } },
  { name: "search_docs", description: "Searches the project documentation and returns matching passages.", inputSchema: { type: "object" } },
];
createInterface({ input: process.stdin }).on("line", (line) => {
  const message = JSON.parse(line);
  if (message.method === "initialize") process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: message.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "clean", version: "1.0.0" } } }) + "\n");
  if (message.method === "tools/list") process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: message.id, result: { tools } }) + "\n");
});
