"""Official Python MCP SDK client: initialize and list tools on one server."""
import asyncio
import sys

from mcp import ClientSession
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client


async def main(url: str, header: str, value: str) -> None:
    client = create_mcp_http_client(headers={header: value})
    async with client, streamable_http_client(url, http_client=client) as streams:
        read, write = streams[0], streams[1]
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print("tools:", len(tools.tools))


asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3]))
