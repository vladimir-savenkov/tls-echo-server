#!/usr/bin/env bash
echo "Generating self-signed certificates..."
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"
echo "Done! Remember to add server.key/crt to .gitignore"

