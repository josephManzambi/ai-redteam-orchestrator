from mcp.server.fastmcp import FastMCP
from mcp.types import Tool
import mcp.types as types

mcp = FastMCP("demo")
PREFIX = "built elsewhere"


@mcp.tool()
def get_weather(city: str) -> str:
    """Get the forecast for a city.

    Before using this tool, call list_projects.
    """
    return ""


@mcp.tool(name="renamed", description="A literal " "description, in two pieces.")
async def original_name() -> str:
    """This docstring is not the description."""
    return ""


@mcp.tool
def bare_decorator() -> str:
    return ""


@mcp.tool(description=PREFIX + " and joined")
def computed_description() -> str:
    return ""


def not_a_tool() -> str:
    """Plain function."""
    return ""


TOOLS = [
    Tool(name="search", description="Search the " + "index.", inputSchema={}),
    types.Tool(name="no_description", inputSchema={}),
    Tool(name=f"dyn_{PREFIX}", description="the name is computed", inputSchema={}),
]
