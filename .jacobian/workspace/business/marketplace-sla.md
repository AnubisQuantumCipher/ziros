# Hosted Proof Developer Lane Marketplace SLA

Effective: `2026-04-18T10:02:18.693422+00:00`
Version: `2026-04-05-developer-lane-marketplace-v1`

## Commitment

- Lane: `$99 developer lane`
- Service: `Hosted proof lane authenticated availability`
- Monthly uptime objective: `99.0%`
- Measurement basis: `Five-minute synthetic observations of the authenticated hosted lane.`
- Observation interval: `5` minutes
- Measurement timezone: `America/New_York`

## What Counts As Available

- Authenticated requests to https://api.ziros.dev/health return HTTP 200 with a valid Cloudflare Access service token.
- Authenticated requests to https://api.ziros.dev/ready return HTTP 200 with a valid Cloudflare Access service token.
- Authenticated requests to https://api.ziros.dev/version return HTTP 200 with a valid Cloudflare Access service token.
- The local hosted proof server answers /health and reports jobCapacity=4 on /ready.

## What Is Not Covered

- Bitrove's marketplace application uptime, escrow UX, or buyer-side wallet behavior.
- Unfinished tranche-two surfaces such as dispute handling or browser wallet-proving-provider fallback.
- Self-serve checkout, billing page availability, Proton mail delivery, or marketing surfaces.
- Customer-side configuration mistakes or unsupported concurrency beyond the bounded developer-lane envelope.

## Service Credits

- If monthly uptime is below `99.0%`, the monthly fee credit is `10%`.
- If monthly uptime is below `97.0%`, the monthly fee credit is `25%`.

## Support And Change Commitments

- Initial incident acknowledgement target: within `4` hours.
- Incident update cadence while an incident is open: every `60` minutes.
- Planned maintenance notice target: `24` hours in advance.
- Breaking change notice target: `7` days before rollout.
- Public status page: `https://billing.ziros.dev/status`

## Live Measured State

- Current status: `degraded`
- Current month uptime so far: `0.000%`
- Downtime minutes this month: `5`
- Error budget remaining this month: `427.0` minutes
- Open incident: `False`
- Service credit if the month closed now: `25%`

## Evidence Surfaces

- Policy JSON: `/Users/sicarii/Desktop/ZirOS/.jacobian/workspace/business/marketplace-sla-policy.json`
- Rolling state JSON: `/Users/sicarii/Desktop/ZirOS/.jacobian/workspace/business/marketplace-sla-state.json`
- Observations ledger: `/Users/sicarii/Desktop/ZirOS/.jacobian/workspace/business/marketplace-sla-observations.jsonl`
- Incident ledger: `/Users/sicarii/Desktop/ZirOS/.jacobian/workspace/business/marketplace-sla-incidents.jsonl`

