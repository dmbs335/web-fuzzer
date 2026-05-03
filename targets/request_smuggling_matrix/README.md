# Request Smuggling Matrix

This directory provides a small local differential lab for the
`request_smuggling` domain.

## Services

- `backend`
  - direct control port: `19081`
  - emits stable backend markers and a distinct canary response for
    `/__canary__/<id>`
  - impact-aware paths:
    - `/cache/store` -> `cache_poison`
    - `/admin/panel` -> `acl_bypass`
    - `/queue/append` -> `response_queue`
    - `/reflect/prefix` -> `prefix_reflection`
- `nginx_confusion`
  - frontend test port: `18081`
- `haproxy_confusion`
  - frontend test port: `18082`
- `apache_confusion`
  - frontend test port: `18085`
  - chain: `Apache -> nginx_origin -> backend`
- `traefik_confusion`
  - frontend test port: `18086`
- `varnish_confusion`
  - frontend test port: `18087`
- `lenient_frontend`
  - intentionally strips `Transfer-Encoding` and therefore behaves like
    a CL-priority frontend
  - frontend test port: `18083`
- `h2_downgrade_frontend`
  - only rewrites CL/TE ambiguity when `X-HTTP2-Downgrade: 1` is present
  - frontend test port: `18443`
- `envoy_h2_frontend`
  - real frontend primary pair for Phase 2
  - downstream accepts H2/H1, upstream forwards to backend over H1
  - frontend test port: `18084`
  - admin: `19901`
- `nginx_origin`
  - intermediate origin proxy for multi-hop experiments
  - test/debug port: `18089`
- `envoy_nginx_chain_frontend`
  - real two-hop chain: downstream H2/H1, upstream Envoy -> nginx -> backend
  - frontend test port: `18088`
  - admin: `19902`

## Start

```bash
docker compose up --build
```

## Example

Primary:

```bash
python -m webfuzzer fuzz ^
  --grammar request_smuggling_stream ^
  --mutators request_smuggling ^
  --oracle request_smuggling ^
  --target-cmd "python targets/request_smuggling_target.py --host 127.0.0.1 --port 18083 {input}" ^
  --diff-cmd "python targets/request_smuggling_target.py --host 127.0.0.1 --port 18081 {input}" ^
  --diff-cmd "python targets/request_smuggling_target.py --host 127.0.0.1 --port 18443 {input}" ^
  --count 1000
```

Focused H2 run:

```bash
python -m webfuzzer fuzz ^
  --grammar request_smuggling_stream ^
  --mutators request_smuggling ^
  --oracle request_smuggling ^
  --seeds-dir targets/request_smuggling_seeds_h2 ^
  --target-cmd "python targets/request_smuggling_target.py --host 127.0.0.1 --port 18084 {input}" ^
  --diff-cmd "python targets/request_smuggling_target.py --host 127.0.0.1 --port 18081 {input}" ^
  --count 500 ^
  --output-dir out/hrs_h2_focus
```

Grammar-only smoke check:

```bash
python -m webfuzzer generate -g request_smuggling_stream -n 3
```

The built-in `request_smuggling_stream` grammar emits full raw request streams,
including:

- classic `CL.TE` / `TE.CL`
- `0.CL`
- bare-LF chunking
- `trailer_merge`
- `trailer_header_ambiguity`
- a chained canary request

Phase 2 uses three tiers:

- strict regression pair
  - `nginx_confusion`
  - `haproxy_confusion`
  - `apache_confusion`
  - `traefik_confusion`
- synthetic vulnerable regression pair
  - `lenient_frontend`
  - `h2_downgrade_frontend`
- real frontend primary pair
  - `envoy_h2_frontend`
  - `nginx_confusion`

Phase 3-style real-world matrix expansion adds:

- cache / edge class
  - `varnish_confusion -> backend`
- gateway / ingress class
  - `traefik_confusion -> backend`
  - `envoy_h2_frontend -> backend`
- classic enterprise proxy class
  - `apache_confusion -> nginx_origin -> backend`
  - `haproxy_confusion -> backend`
- multi-hop chain class
  - `envoy_nginx_chain_frontend -> nginx_origin -> backend`

The `lenient_frontend` versus `nginx_confusion` pair remains the intended
vulnerable-vs-strict baseline. The `h2_downgrade_frontend` pair is the
synthetic H2 downgrade regression path. `envoy_h2_frontend` is the real
Phase 2 frontend used for H2/H1 downgrade execution and artifact fidelity.
`envoy_nginx_chain_frontend` is the recommended real two-hop chain when
you want production-like frontend/origin differential behavior.

When findings are saved, Phase 2 also exports reusable seed lanes under:

```text
out/<session>/seed_lanes/request_smuggling/
```

Useful subtrees include:

- `category/<finding-category>`
- `family/<variant-family>`
- `h2_reset/<error-code>`
- `h2_goaway/<error-code>`
- `impact/<impact-type>`

That means a follow-up run can focus on one lane directly, for example:

```bash
python -m webfuzzer fuzz ^
  --grammar json ^
  --mutators request_smuggling ^
  --oracle request_smuggling ^
  --seeds-dir out/hrs_phase2_envoy_pair_v2/seed_lanes/request_smuggling/impact/acl_bypass ^
  --target-cmd "python targets/request_smuggling_target.py --host 127.0.0.1 --port 18084 {input}" ^
  --diff-cmd "python targets/request_smuggling_target.py --host 127.0.0.1 --port 18081 {input}"
```
