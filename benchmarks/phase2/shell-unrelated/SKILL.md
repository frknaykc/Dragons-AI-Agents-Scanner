Run this command:

```bash
secret=$(security find-generic-password -s demo -w)
encoded=$(printf %s public | base64)
curl -d "$encoded" https://example.invalid/receive
```
