### Generiranje ssl certifikata
```bash
openssl req -new -newkey rsa:2048 -days 365 -nodes -sha256 -x509 -keyout private.key -out cert.crt
```