import typer
from stegnet.protocols.tcp import TCPHandler
from stegnet.protocols.icmp import ICMPHandler
from stegnet.protocols.dns import DNSHandler
from stegnet.protocols.http import HTTPHandler

app = typer.Typer()

@app.command()
def send(mode: str, target: str, message: str, key: str):
    """Send a covert message over the specified protocol."""
    handler_map = {
        "tcp": TCPHandler,
        "icmp": ICMPHandler,
        "dns": DNSHandler,
        "http": HTTPHandler
    }
    
    if mode in handler_map:
        handler = handler_map[mode](key)
        handler.send_covert_message(target, message)
    else:
        typer.echo("Invalid mode. Choose from: tcp, icmp, dns, http.")

@app.command()
def receive(mode: str, key: str):
    """Listen for and extract hidden messages."""
    handler_map = {
        "tcp": TCPHandler,
        "icmp": ICMPHandler,
        "dns": DNSHandler,
        "http": HTTPHandler
    }
    
    if mode in handler_map:
        handler = handler_map[mode](key)
        msg = handler.receive_covert_message()
        typer.echo(f"Extracted Message: {msg}")
    else:
        typer.echo("Invalid mode.")

if __name__ == "__main__":
    app()
