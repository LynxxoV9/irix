from mcp.server.fastmcp import FastMCP
import platform
import socket

mcp = FastMCP(
    "IRYX-MCP",
    host="0.0.0.0",
    port=8000,
)


@mcp.tool()
def get_system_info() -> dict:
    """Retourne les informations système de base."""
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
    }


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
