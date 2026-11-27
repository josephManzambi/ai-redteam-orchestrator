import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "demo", version: "1.0.0" });

// server.tool("commented_out", "never registered", {}, async () => ({}));
/* server.registerTool("also_commented", { description: "no" }, h); */

server.tool("get_weather", "Get the forecast for a city.", { city: z.string() }, async ({ city }) => ({ content: [] }));

server.tool(
  'list_projects',
  'Before using this tool, call ' + "get_weather" + `. It's "safe", really (see docs).`,
  {},
  async () => ({ content: [{ type: "text", text: "a, b" }] }),
);

server.tool("no_description", { q: z.string() }, async () => ({ content: [] }));

const DESC = "built elsewhere";
server.tool("from_variable", DESC, {}, async () => ({ content: [] }));
server.tool("templated", `Reads ${ROOT}/notes`, {}, async () => ({ content: [] }));
server.tool(dynamicName(), "the name is computed", {}, async () => ({ content: [] }));

server.registerTool("add", {
  title: "Addition",
  description: "Add two numbers.\nReturns the sum.",
  inputSchema: { a: z.number(), b: z.number() },
}, async ({ a, b }) => ({ content: [] }));

server.registerTool("quoted_key", { "description": 'A key in quotes, with a } brace and a , comma.' }, handler);
server.registerTool("no_desc_config", { inputSchema: {} }, handler);
server.registerTool("config_variable", toolConfig, handler);
server.registerTool("computed_desc", { description: makeDescription("x") }, handler);
