"""Exercise both TLS binaries and a normal server shutdown in sanitizer CI."""

import argparse
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path


def wait_for_server(server, port):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if server.poll() is not None:
            raise RuntimeError(f"server exited before accepting connections: {server.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("server did not start within 10 seconds")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_dir", type=Path)
    args = parser.parse_args()
    build_dir = args.build_dir.resolve()

    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        cert = work / "server.crt"
        key = work / "server.key"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(cert), "-days", "1",
             "-subj", "/CN=localhost"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]

        with (work / "server.out").open("w+") as server_output:
            server = subprocess.Popen(
                [str(build_dir / "server"), "--cert", str(cert), "--key", str(key),
                 "--port", str(port), "--threads", "4", "--log-file",
                 str(work / "server.log")],
                stdout=server_output, stderr=subprocess.STDOUT,
            )
            try:
                wait_for_server(server, port)
                client = subprocess.run(
                    [str(build_dir / "client"), "--host", "localhost", "--port",
                     str(port), "--clients", "20", "--threads", "4", "--packets",
                     "5", "--log-file", str(work / "client.log")],
                    capture_output=True, text=True, timeout=30,
                )
                print(client.stdout, end="")
                print(client.stderr, end="")
                if client.returncode != 0:
                    raise RuntimeError(f"client exited with code {client.returncode}")
                if "Completed clients: 20/20; packets received: 100/100" not in client.stdout:
                    raise RuntimeError("client did not complete all packets")

                server.send_signal(signal.SIGTERM)
                if server.wait(timeout=10) != 0:
                    raise RuntimeError(f"server exited with code {server.returncode}")
            finally:
                if server.poll() is None:
                    server.kill()
                    server.wait()
                server_output.seek(0)
                print(server_output.read(), end="")


if __name__ == "__main__":
    main()
