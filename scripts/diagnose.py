#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""deliverability_diagnose.py - read-only email deliverability diagnostic.

Reads .eml files (never sends anything, never calls the network) and prints a
scored fix list covering authentication, compliance, content risk and hygiene.

  python3 deliverability_diagnose.py --eml sample.eml --format md
  python3 deliverability_diagnose.py --eml a.eml b.eml --json --out r.json
  python3 deliverability_diagnose.py --selftest
"""
from __future__ import annotations
import argparse, email, json, re, sys
from email import policy

SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly")
SPAM_SUBJECT = ("free", "act now", "limited time", "guarantee", "risk-free", "winner",
                "cash", "urgent", "100%", "click here", "buy now")

CHECK_WEIGHT = {
    "auth_results_missing": 14,
    "spf_fail": 18, "dkim_fail": 18, "dmarc_fail": 20,
    "alignment_mismatch": 10,
    "no_unsubscribe": 12, "no_unsubscribe_post": 5,
    "no_plain_text": 8,
    "image_heavy": 8,
    "too_many_links": 6,
    "shortener": 6,
    "subject_caps": 5, "subject_punct": 4, "subject_spamword": 6,
    "no_date": 4, "no_message_id": 3,
}

def _text_parts(msg):
    plain = html = ""
    if msg.is_multipart():
        for p in msg.walk():
            ct = p.get_content_type()
            if ct == "text/plain" and not plain:
                try: plain = p.get_content()
                except Exception: plain = ""
            elif ct == "text/html" and not html:
                try: html = p.get_content()
                except Exception: html = ""
    else:
        ct = msg.get_content_type()
        try: body = msg.get_content()
        except Exception: body = ""
        if ct == "text/html": html = body
        else: plain = body
    return plain, html

def _strip(h):
    return re.sub(r"<[^>]+>", " ", h or "")

def _links(html, plain):
    urls = re.findall(r"https?://[^\s\"'<>)]+", html or "")
    urls += re.findall(r"https?://[^\s\"'<>)]+", plain or "")
    return urls

def analyze(raw: bytes, name: str = "") -> dict:
    msg = email.message_from_bytes(raw, policy=policy.default)
    hits, fixes = [], []
    score = 100

    def hit(code, msgtext, fix):
        nonlocal score
        hits.append({"code": code, "detail": msgtext})
        score -= CHECK_WEIGHT.get(code, 5)
        if fix: fixes.append(fix)

    # authentication
    auth = " ".join(msg.get_all("Authentication-Results") or []).lower()
    if not auth:
        hit("auth_results_missing", "no Authentication-Results header", 
            "Pull the raw header from a real inbox (Gmail: Show original) - without it you cannot see SPF/DKIM/DMARC verdicts.")
    else:
        if "spf=fail" in auth or "spf=softfail" in auth:
            hit("spf_fail", "SPF did not pass", "Publish or fix the SPF record so the sending IP is listed; keep it under 10 DNS lookups.")
        if "dkim=fail" in auth:
            hit("dkim_fail", "DKIM did not pass", "Re-sign with the selector your DNS actually publishes; check key length >= 1024 and rotate after any ESP change.")
        if "dmarc=fail" in auth:
            hit("dmarc_fail", "DMARC did not pass", "Align the From domain with the signing domain, or relax the DMARC policy from p=reject to p=quarantine while you fix alignment.")

    frm = email.utils.parseaddr(msg.get("From", ""))[1]
    ret = email.utils.parseaddr(msg.get("Return-Path", ""))[1]
    fdom = frm.split("@")[-1].lower() if "@" in frm else ""
    rdom = ret.split("@")[-1].lower() if "@" in ret else ""
    if fdom and rdom and fdom != rdom and not rdom.endswith("." + fdom):
        hit("alignment_mismatch", "From domain %s differs from Return-Path %s" % (fdom, rdom),
            "Send through a subdomain of the From domain (mail.example.com) so SPF and DKIM both align.")

    # compliance
    if not msg.get("List-Unsubscribe"):
        hit("no_unsubscribe", "no List-Unsubscribe header",
            "Add List-Unsubscribe with a mailto: and an https: one-click target; Gmail and Yahoo require it for bulk senders.")
    elif not msg.get("List-Unsubscribe-Post"):
        hit("no_unsubscribe_post", "List-Unsubscribe present but no List-Unsubscribe-Post",
            "Add List-Unsubscribe-Post: List-Unsubscribe=One-Click so the mailbox provider can unsubscribe without a page visit.")

    # content
    plain, html = _text_parts(msg)
    if html and not plain:
        hit("no_plain_text", "HTML-only message, no text/plain alternative",
            "Add a text/plain part. HTML-only mail scores worse with most filters and breaks in text clients.")
    imgs = len(re.findall(r"<img\b", html or "", re.I))
    text_len = len(_strip(html).strip()) or len((plain or "").strip())
    if imgs >= 3 and text_len < imgs * 120:
        hit("image_heavy", "%d images vs %d chars of text" % (imgs, text_len),
            "Raise the text-to-image ratio: one image per ~200 words of real copy, and never send an image-only email.")
    urls = _links(html, plain)
    if len(urls) > 12:
        hit("too_many_links", "%d links in one message" % len(urls),
            "Cut to the links that matter (usually 3-6). High link density is a classic bulk-mail signal.")
    short = [u for u in urls if any(s in u for s in SHORTENERS)]
    if short:
        hit("shortener", "shortener in use: %s" % short[0][:60],
            "Replace URL shorteners with your own tracked domain; shorteners are widely blocklisted.")

    subj = msg.get("Subject", "") or ""
    letters = [c for c in subj if c.isalpha()]
    if letters and sum(1 for c in letters if c.isupper()) / len(letters) > 0.6 and len(letters) > 8:
        hit("subject_caps", "subject is mostly uppercase", "Write the subject in sentence case; all-caps is a spam signal.")
    if subj.count("!") >= 2 or "$$$" in subj:
        hit("subject_punct", "subject has repeated ! or $$$", "Use at most one exclamation mark.")
    low = subj.lower()
    bad = [w for w in SPAM_SUBJECT if w in low]
    if bad:
        hit("subject_spamword", "subject contains: %s" % ", ".join(bad[:3]),
            "Rewrite the subject without promotional trigger words; lead with the specific outcome instead.")

    # hygiene
    if not msg.get("Date"):
        hit("no_date", "no Date header", "Set a real Date header; missing Date is a strong forgery signal.")
    if not msg.get("Message-ID"):
        hit("no_message_id", "no Message-ID header", "Let your ESP set Message-ID; hand-rolled or missing IDs get filtered.")

    score = max(0, min(100, score))
    band = "healthy" if score >= 85 else ("watch" if score >= 60 else "damaged")
    return {"file": name, "subject": subj[:120], "from": frm, "return_path": ret,
            "score": score, "band": band, "hits": hits, "fixes": fixes,
            "links": len(urls), "images": imgs, "text_chars": text_len}

SAMPLE = b"""From: Shop <hello@shop.example>
To: buyer@example.com
Subject: LAST CHANCE!!! 100% FREE SHIPPING
Date: Mon, 1 Jan 2026 10:00:00 +0000
Message-ID: <x@shop.example>
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body><img src="a.png"><img src="b.png"><img src="c.png">
<a href="https://bit.ly/x">click here</a></body></html>
"""

def selftest():
    ok = 0
    r = analyze(SAMPLE, "sample.eml")
    assert r["band"] == "damaged", r["band"]; ok += 1
    codes = {h["code"] for h in r["hits"]}
    assert "no_unsubscribe" in codes; ok += 1
    assert "no_plain_text" in codes; ok += 1
    assert "shortener" in codes; ok += 1
    assert "subject_caps" in codes or "subject_spamword" in codes; ok += 1
    assert r["fixes"] and len(r["fixes"]) >= 5; ok += 1
    # a clean message must score healthy
    clean = b"""From: Team <team@example.com>
Return-Path: <bounce@mail.example.com>
Subject: Your January release notes
Date: Mon, 1 Jan 2026 10:00:00 +0000
Message-ID: <y@mail.example.com>
List-Unsubscribe: <mailto:u@example.com>, <https://example.com/u>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="b1"

--b1
Content-Type: text/plain

Hello, here are the January notes. Details at https://example.com/notes
--b1
Content-Type: text/html

<html><body><p>Hello, here are the January notes.</p><p><a href="https://example.com/notes">Read them</a></p></body></html>
--b1--
"""
    r2 = analyze(clean, "clean.eml")
    assert r2["band"] == "healthy", (r2["band"], r2["hits"]); ok += 1
    assert r2["score"] == 100, r2["score"]; ok += 1
    print("selftest %d/8" % ok)
    return ok == 8

def to_md(results):
    L = []
    for r in results:
        L += ["## %s" % (r["file"] or r["subject"] or "message"), "",
              "- Score: **%d/100** (%s)" % (r["score"], r["band"]),
              "- From: `%s` | Return-Path: `%s`" % (r["from"] or "-", r["return_path"] or "-"),
              "- Links: %d | Images: %d | Text chars: %d" % (r["links"], r["images"], r["text_chars"]), ""]
        if r["hits"]:
            L.append("**Findings**")
            L += ["- `%s` %s" % (h["code"], h["detail"]) for h in r["hits"]]
            L += ["", "**Fix in this order**"]
            L += ["%d. %s" % (i + 1, f) for i, f in enumerate(r["fixes"])]
        else:
            L.append("No blocking findings. Keep the authentication chain and unsubscribe headers in place.")
        L.append("")
    return "\n".join(L)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--eml", nargs="*", help="one or more .eml files")
    ap.add_argument("--format", choices=["md", "json"], default="md")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", help="write output to this path")
    ap.add_argument("--fail-under", type=int, default=None)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return 0 if selftest() else 1
    if not a.eml:
        ap.error("--eml is required (or use --selftest)")
    results = []
    for p in a.eml:
        with open(p, "rb") as f:
            results.append(analyze(f.read(), p))
    if a.json or a.format == "json":
        out = json.dumps(results, ensure_ascii=False, indent=1)
    else:
        out = to_md(results)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(out)
        print("written %s" % a.out)
    else:
        print(out)
    if a.fail_under is not None and min(r["score"] for r in results) < a.fail_under:
        return 2
    return 0

if __name__ == "__main__":
    sys.exit(main())
