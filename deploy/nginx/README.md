# Optional Nginx rate-limit edge

The local Compose stack includes an optional Nginx edge profile with per-IP limits for authentication, workspace invitations, and general API traffic.

Start the stack through the edge proxy:

```bash
docker compose -f docker-compose.local.yml --profile edge up --build
```

Open the app through `http://localhost:8080`. The Next.js container still has its development/local port mapping on `127.0.0.1:3000`; do not expose that port directly to the public internet when using the edge profile. For production, terminate TLS at this proxy or at a trusted upstream load balancer and expose only the intended public listener. If TLS terminates before Next.js, set `SATARK_PUBLIC_ORIGIN` to the canonical external origin (for example `https://satark.example`) so the same-origin CSRF boundary uses the browser-visible scheme rather than the internal HTTP hop.

## Trusted client IPs

By default, Nginx rate-limits on the direct peer address (`$remote_addr`). If another load balancer or CDN is in front of Nginx, configure the real-IP module with the exact trusted proxy CIDRs and the header that your provider overwrites. For example, adapt these directives to your actual network:

```nginx
set_real_ip_from 10.20.0.0/16;  # replace with the actual proxy subnet
real_ip_header X-Forwarded-For;
real_ip_recursive on;
```

Never trust arbitrary `X-Forwarded-For` values or use broad public CIDRs. A spoofable client IP defeats per-IP rate limits.

## Default limits

- Authentication and recovery endpoints: 10 requests/minute/IP with a burst of 10.
- Workspace invitation creation: same authentication limit; the backend also caps invitations at 20 per workspace/hour.
- General API: 120 requests/minute/IP with a burst of 120.
- Concurrent connections: 20 per IP.
- Oversized request bodies are rejected at 8 MiB before reaching Next.js.

Tune these values to the deployment's expected traffic and test legitimate bulk workflows before production. These limits reduce application-level abuse; they do not replace a managed WAF, DDoS protection, network ACLs, or provider-side abuse controls.
