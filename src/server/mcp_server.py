from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from .providers.tool_base import IndicatorType
from .providers import get_provider, get_all_providers

mcp = FastMCP("Threat Intel MCP Server", json_response=True)


@mcp.tool()
async def query_provider(
    provider_name: str,
    indicator: str,
    indicator_type: IndicatorType = "ip",
):
    """
    שאילתה לפרוביידר אחד ספציפי.
    example: provider_name='virustotal', indicator='8.8.8.8'
    """
    provider = get_provider(provider_name)
    return await provider.query(indicator, indicator_type)


@mcp.tool()
async def query_all_providers(
    indicator: str,
    indicator_type: IndicatorType = "ip",
):
    """
    שאילתה לכל הפרוביידרים הרשומים ב-registry ומאחדת את התוצאות.
    """
    results = []
    for provider in get_all_providers():
        try:
            res = await provider.query(indicator, indicator_type)
            results.append(res)
        except Exception as e:
            results.append(
                {
                    "provider": provider.name,
                    "indicator": indicator,
                    "indicator_type": indicator_type,
                    "error": str(e),
                }
            )
    return results


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
