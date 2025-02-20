import typer
from stegnet.protocols.tcp import TCPHandler
from stegnet.protocols.icmp import ICMPHandler
from stegnet.protocols.dns import DNSHandler
from stegnet.protocols.http import HTTPHandler

app = typer.Typer()

@app.command()
def send(
    mode: str = typer.Option(..., help="Mode of communication: tcp, icmp, dns, http"),
    target: str = typer.Option(..., help="Target IP or domain"),
    message: str = typer.Option(..., help="Message to send covertly"),
    key: str = typer.Option(..., help="Encryption key for securing the message")
):
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
        typer.echo(f"[*] Covert message sent via {mode} to {target}")
    else:
        typer.echo("Invalid mode. Choose from: tcp, icmp, dns, http.")

@app.command()
def receive(
    mode: str = typer.Option(..., help="Mode of communication: tcp, icmp, dns, http"),
    key: str = typer.Option(..., help="Encryption key for decryption")
):
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
        if msg:
            typer.echo(f"[+] Extracted Message: {msg}")
        else:
            typer.echo("[*] No message extracted.")
    else:
        typer.echo("Invalid mode. Choose from: tcp, icmp, dns, http.")

if __name__ == "__main__":
    app()
