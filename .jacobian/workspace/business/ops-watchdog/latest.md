# Ops Drift Report — 2026-04-18

Generated: `2026-04-18T10:02:39.142682+00:00`
Global status: `blocked`
Shared health status: `degraded`

## Outward Readiness

- Ready lanes: `none`
- Blocked lanes: `discord-community, newsletter-pipeline, twitter-evening, twitter-morning`

## Drift Summary

- Truth-surface drift: `Business Dashboard Freshness, CTA Click Attribution Surface, Claim Surface Local, Cost Monitor Freshness, Lead Pipeline Freshness, Midnight Pain Monitor Freshness, Money Path Smoke Freshness, Promotion Planner Freshness, Proof Usage Freshness, Proton Drive Archive Freshness, Restore Drill Freshness, Self-Serve Gate Freshness`
- Dependency drift: `Billing Service Local, Billing Service Public, Ghost CMS, Hosted Lane SLA Objective, Metering Proxy Port, Outward Gate Status: discord-community, Outward Gate Status: newsletter-pipeline, Outward Gate Status: twitter-evening, Outward Gate Status: twitter-morning, Proof Queue Capacity, Proof Server Health, Proton Bridge Ready, Proton Bridge SMTP, Proton Custom Domain DNS, Proton SMTP Token Ready, Public Edge Watchdog State, Stripe Webhook Secret, Tracked Redirect Local, Tracked Redirect Port, Tracked Redirect Public, discord-community: Billing Hosted Public, discord-community: Billing Service Local, discord-community: Cloudflare Access Edge, discord-community: Planner Freshness, discord-community: Proof Queue Capacity, discord-community: Proof Server Local, discord-community: Self-Serve Checkout Path, discord-community: Tracked Redirect Local, discord-community: Tracked Redirect Public, newsletter-pipeline: Billing Hosted Public, newsletter-pipeline: Billing Service Local, newsletter-pipeline: Cloudflare Access Edge, newsletter-pipeline: Planner Freshness, newsletter-pipeline: Proof Queue Capacity, newsletter-pipeline: Proof Server Local, newsletter-pipeline: Self-Serve Checkout Path, newsletter-pipeline: Tracked Redirect Local, newsletter-pipeline: Tracked Redirect Public, twitter-evening: Billing Hosted Public, twitter-evening: Billing Service Local, twitter-evening: Cloudflare Access Edge, twitter-evening: Planner Freshness, twitter-evening: Proof Queue Capacity, twitter-evening: Proof Server Local, twitter-evening: Self-Serve Checkout Path, twitter-evening: Tracked Redirect Local, twitter-evening: Tracked Redirect Public, twitter-morning: Billing Hosted Public, twitter-morning: Billing Service Local, twitter-morning: Cloudflare Access Edge, twitter-morning: Planner Freshness, twitter-morning: Proof Queue Capacity, twitter-morning: Proof Server Local, twitter-morning: Self-Serve Checkout Path, twitter-morning: Tracked Redirect Local, twitter-morning: Tracked Redirect Public`
- Auth/runtime drift: `Cloudflare Access Edge, Keychain: discord-bot-token, Keychain: ghost-admin-api-key, Keychain: github-pat, Keychain: openai-media-api-key, Keychain: stripe-secret-key, discord-community: Discord Auth Probe, newsletter-pipeline: Ghost Admin Probe, twitter-evening: Twitter Auth Material, twitter-morning: Twitter Auth Material`

## Immediate Blockers

- discord-community: Planner Freshness, Proof Server Local, Proof Queue Capacity, Cloudflare Access Edge, Tracked Redirect Local, Tracked Redirect Public, Billing Service Local, Billing Hosted Public, Self-Serve Checkout Path, Discord Auth Probe
- newsletter-pipeline: Planner Freshness, Proof Server Local, Proof Queue Capacity, Cloudflare Access Edge, Tracked Redirect Local, Tracked Redirect Public, Billing Service Local, Billing Hosted Public, Self-Serve Checkout Path, Ghost Admin Probe
- twitter-evening: Planner Freshness, Proof Server Local, Proof Queue Capacity, Cloudflare Access Edge, Tracked Redirect Local, Tracked Redirect Public, Billing Service Local, Billing Hosted Public, Self-Serve Checkout Path, Twitter Auth Material
- twitter-morning: Planner Freshness, Proof Server Local, Proof Queue Capacity, Cloudflare Access Edge, Tracked Redirect Local, Tracked Redirect Public, Billing Service Local, Billing Hosted Public, Self-Serve Checkout Path, Twitter Auth Material

## Notes

- Shared failed checks: `Keychain: ghost-admin-api-key, Keychain: discord-bot-token, Keychain: stripe-secret-key, Keychain: github-pat, Keychain: openai-media-api-key, Ghost CMS, Proton Bridge SMTP, Metering Proxy Port, Tracked Redirect Port, Business Dashboard Freshness, Proof Server Health, Proof Queue Capacity, Cloudflare Access Edge, Proof Usage Freshness, Midnight Pain Monitor Freshness, Promotion Planner Freshness, Tracked Redirect Local, Tracked Redirect Public, Lead Pipeline Freshness, CTA Click Attribution Surface, Outward Gate Status: twitter-morning, Outward Gate Status: twitter-evening, Outward Gate Status: discord-community, Outward Gate Status: newsletter-pipeline, Proton Bridge Ready, Proton SMTP Token Ready, Proton Custom Domain DNS, Proton Drive Archive Freshness, Public Edge Watchdog State, Billing Service Local, Billing Service Public, Claim Surface Local, Stripe Webhook Secret, Self-Serve Gate Freshness, Money Path Smoke Freshness, Restore Drill Freshness, Hosted Lane SLA Objective, Cost Monitor Freshness`
- Planner-driven lanes currently represented: `discord-community, newsletter-pipeline, twitter-evening, twitter-morning`
- Watchdog stale: `False`

