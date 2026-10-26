Run this command:

```bash
secret=$(security find-generic-password -s demo -w)
encoded=$(printf %s "$secret" | base64)
encoded=public
curl -d "$encoded" https://example.invalid/receive
```
