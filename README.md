# email-deliverability-diagnose

**Score any `.eml` against the rules that actually decide inbox vs. spam — offline, read-only, nothing is ever sent.**

[![no network](https://img.shields.io/badge/network-none-brightgreen)](#what-it-does-not-do)
[![python](https://img.shields.io/badge/python-3.8%2B-blue)](#requirements)
[![license](https://img.shields.io/badge/license-MIT-black)](LICENSE)

---

## Why this exists

When a campaign lands in spam, the raw email in your inbox already contains the answer — the `Authentication-Results` header, the missing `List-Unsubscribe`, the HTML-only body, the subject line with three exclamation marks. Most people never read it, because the header is 40 lines of noise.

This tool reads that header for you and returns a ranked fix list. It is the first 5 minutes of any deliverability investigation.

## What it does

```
python3 scripts/diagnose.py --eml examples/bad-campaign.eml --format md
```

Real output from the bundled example:

```
## examples/bad-campaign.eml

- Score: **53/100** (damaged)
- From: `growth@mailer.example-co.com` | Return-Path: `-`
- Links: 1 | Images: 1 | Text chars: 74

**Findings**
- `auth_results_missing` no Authentication-Results header
- `no_unsubscribe` no List-Unsubscribe header
- `no_plain_text` HTML-only message, no text/plain alternative
- `subject_punct` subject has repeated ! or $$$
- `subject_spamword` subject contains: act now, guarantee
- `no_message_id` no Message-ID header

**Fix in this order**
1. Pull the raw header from a real inbox (Gmail: Show original) - without it you cannot see SPF/DKIM/DMARC verdicts.
2. Add List-Unsubscribe with a mailto: and an https: one-click target; Gmail and Yahoo require it for bulk senders.
3. Add a text/plain part. HTML-only mail scores worse with most filters and breaks in text clients.
4. Use at most one exclamation mark.
5. Rewrite the subject without promotional trigger words; lead with the specific outcome instead.
6. Let your ESP set Message-ID; hand-rolled or missing IDs get filtered.
```

Other output modes:

```bash
python3 scripts/diagnose.py --eml a.eml b.eml --json --out report.json   # machine readable
python3 scripts/diagnose.py --selftest                                    # 8/8 assertions
```

## What it checks

| Group | Signals |
|---|---|
| **Authentication** | `Authentication-Results` present, SPF / DKIM / DMARC verdicts, `Return-Path` alignment |
| **Compliance** | `List-Unsubscribe` (mailto + one-click https), `List-Unsubscribe-Post`, unsubscribe placement |
| **Content risk** | Subject punctuation and trigger words, text-to-image ratio, HTML-only bodies, link count |
| **Hygiene** | `Message-ID`, `Date`, `MIME-Version`, malformed `Content-Type` charset quoting |
| **Structure** | MIME tree integrity, missing `text/plain` alternative, oversized single image |
| **Headers** | `From` / `Reply-To` alignment, display-name spoofing patterns |

Scoring: each finding carries a weight; the total is normalised to 0–100 and bucketed as `healthy` / `at risk` / `damaged` / `critical`.

## What it does NOT do

- **No network calls.** It never resolves DNS, never queries a blocklist, never talks to an SMTP server.
- **Sends nothing.** Read-only by construction — there is no send code path in the file.
- **No ESP login.** It does not touch your Mailchimp / SendGrid / Klaviyo account.

That is deliberate: you can run it on a production mailbox export on a locked-down machine without any data leaving the box.

## Requirements

Python 3.8+. Standard library only. No `pip install`.

## Getting the raw `.eml`

- **Gmail** — open the message → ⋮ → *Show original* → *Download Original*
- **Outlook** — open → *File* → *Save As* → `.eml`
- **Apple Mail** — *File* → *Save As* → *Raw Message Source*

Then run the tool on that file.

## Where this came from

This script is the free diagnostic core of the **Deliverability Rescue Kit** — a paid pack that adds the authentication checklist, the warm-up and throttle schedule, and the remediation playbook that tells you what to change *after* the score comes back.

→ **Full kit:** https://956231studio.com/packs/deliverability-rescue-kit/
→ **All packs:** https://956231studio.com/packs/

The script here is complete and MIT-licensed. If the score tells you the problem but not the fix, that is what the kit is for.

## License

MIT — see [LICENSE](LICENSE).
