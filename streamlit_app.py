"""
Email Verification Dashboard — Streamlit
Multi-signal confidence engine:
  1. Syntax validation
  2. DNS / MX records
  3. Disposable domain detection
  4. Role-based address detection
  5. SPF record check
  6. DMARC record check
  7. Catch-all detection (SMTP probe on fake address first)
  8. Gravatar presence (real person signal)
  9. Free provider boost (Gmail/Yahoo/Outlook)
 10. Abstract API deep SMTP (optional, via sidebar key)
"""

import re
import time
import socket
import smtplib
import hashlib

import requests
import pandas as pd
import streamlit as st

try:
    import dns.resolver, dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

# ─────────────────────────────────────────────────────────────────────────────
# Page config
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(page_title="Email Verifier", page_icon="✉️", layout="centered")
st.markdown("""
<style>
  .block-container { padding-top: 2rem; }
  .stTabs [data-baseweb="tab"] { font-size: 0.95rem; font-weight: 500; }
  div[data-testid="metric-container"] {
      background: #f8fafc; border: 1px solid #e2e8f0;
      border-radius: 10px; padding: 12px 16px;
  }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────
DNS_TIMEOUT  = 5
SMTP_TIMEOUT = 8
SMTP_FROM    = "verify@verification-check.local"

FREE_PROVIDERS = {
    "gmail.com","googlemail.com","yahoo.com","yahoo.co.in","yahoo.co.uk",
    "yahoo.fr","yahoo.de","yahoo.es","yahoo.it","yahoo.ca","yahoo.com.br",
    "outlook.com","hotmail.com","hotmail.co.uk","hotmail.fr","hotmail.de",
    "live.com","live.co.uk","msn.com","icloud.com","me.com","mac.com",
    "protonmail.com","proton.me","tutanota.com","zoho.com","aol.com",
    "rediffmail.com","yandex.com","yandex.ru","mail.ru","inbox.ru",
}

DISPOSABLE_DOMAINS = {
    "mailinator.com","guerrillamail.com","guerrillamail.net","guerrillamail.org",
    "tempmail.com","temp-mail.org","throwam.com","trashmail.com","trashmail.at",
    "trashmail.io","trashmail.me","trashmail.net","dispostable.com",
    "yopmail.com","yopmail.fr","fakeinbox.com","mailnull.com","spamgourmet.com",
    "10minutemail.com","10minutemail.net","10minutemail.org","maildrop.cc",
    "discard.email","spam4.me","mailsac.com","sharklasers.com","guerrillamailblock.com",
    "grr.la","guerrillamail.io","spamgourmet.net","spamgourmet.org",
    "trashmail.com","trashmail.de","trashmail.org","trashmail.net","trashmail.at",
    "trashmail.io","trashmail.me","trashmail.xyz","trashmail.app",
    "getairmail.com","filzmail.com","throwam.com","tempr.email","discard.email",
    "spamex.com","spamfree24.org","binkmail.com","bob.email","clrmail.com",
    "dayrep.com","deadaddress.com","dumpmail.de","e4ward.com","emailgo.de",
    "emailtemporanea.com","emkei.cz","fakedemail.com","fakemailz.com",
    "flurre.com","flyspam.com","getmails.eu","gishpuppy.com","hmamail.com",
    "ieatspam.eu","ignoremail.com","inboxalias.com","incognitomail.com",
    "jetable.com","jetable.fr.nf","jetable.net","jnxjn.com","junk.to",
    "kasmail.com","keepmymail.com","killmail.com","kurzepost.de","lhsdv.com",
    "mailin8r.com","mailinator.net","mailinator2.com","mailismagic.com",
    "mailtemporal.com","mailtemporaire.com","mailtome.de","mailtrash.net",
    "mbx.cc","meltmail.com","mintemail.com","mytrashmail.com","nabuma.com",
    "netmails.com","netzidiot.de","noclickemail.com","nomail.pw","nospam4.us",
    "nowmymail.com","objectmail.com","odaymail.com","onewaymail.com",
    "opentrash.com","pancakemail.com","pookmail.com","privacy.net",
    "proxymail.eu","quickinbox.com","rcpt.at","recyclemail.dk",
    "sandelf.de","selfdestructingmail.com","sendspamhere.com","shiftmail.com",
    "sinnlos-mail.de","skeefmail.com","slopsbox.com","snakemail.com",
    "sneakemail.com","sofort-mail.de","spam.la","spam.su","spamavert.com",
    "spambob.com","spambox.us","spamcannon.com","spamcero.com","spamday.com",
    "spamfree.eu","spamgoes.in","spamhole.com","spamify.com","spaml.com",
    "spammotel.com","spamsalad.in","spamspot.com","spamstack.net","spamtroll.net",
    "spoofmail.de","tempail.com","tempalias.com","tempemail.com","tempimbox.com",
    "tempinbox.com","tempmail.eu","tempmail.it","tempmail.us","tempmail2.com",
    "tempomail.fr","temporaryemail.com","temporaryinbox.com","throwaway.email",
    "tmail.com","tmail.io","tmailinator.com","toiea.com","trashcanmail.com",
    "trashdevil.com","trashemail.de","trashinbox.com","trashmailer.com",
    "trbvm.com","trnksmail.se","twinmail.de","umail.net","vaultmail.com",
    "webemail.me","wegwerfemail.com","wegwerfmail.de","willselfdestruct.com",
    "xagloo.com","xemaps.com","xmail.pw","yapped.net","zehnminuten.de",
    "zehnminutenmail.de","zippymail.info","zoemail.com","zomg.info",
}

ROLE_PREFIXES = {
    "admin","administrator","abuse","billing","contact","help","info",
    "mailer","mailer-daemon","marketing","news","newsletter","no-reply",
    "noreply","notify","notifications","postmaster","privacy","reply",
    "sales","security","service","support","system","team","test",
    "unsubscribe","webmaster","hello","office","operations","hr",
    "accounts","careers","feedback","jobs","legal","media","press",
    "recruitment","root","spam","subscribe","sysadmin","techsupport",
}

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

# ─────────────────────────────────────────────────────────────────────────────
# SIGNAL 1 — Syntax
# ─────────────────────────────────────────────────────────────────────────────
def check_syntax(email):
    if not email: return False, "Empty address"
    if email.count("@") != 1:
        return False, f"Invalid — {email.count('@')} '@' characters found"
    local, domain = email.split("@", 1)
    if not local: return False, "Missing local part (before @)"
    if not domain or "." not in domain: return False, "Domain missing or no TLD"
    if not _EMAIL_RE.match(email): return False, "Fails RFC-5321 syntax check"
    return True, "Syntax valid"

# ─────────────────────────────────────────────────────────────────────────────
# SIGNAL 2 — DNS / MX
# ─────────────────────────────────────────────────────────────────────────────
def get_mx(domain):
    if not HAS_DNS:
        try:
            socket.setdefaulttimeout(DNS_TIMEOUT)
            socket.gethostbyname(domain)
            return [domain], "A-record found (fallback)"
        except socket.gaierror as e:
            return [], str(e)
    r = dns.resolver.Resolver(); r.lifetime = DNS_TIMEOUT
    try:
        ans = r.resolve(domain, "MX")
        hosts = [str(a.exchange).rstrip(".") for a in sorted(ans, key=lambda x: x.preference)]
        return hosts, f"{len(hosts)} MX record(s)"
    except dns.resolver.NXDOMAIN: return [], "Domain does not exist (NXDOMAIN)"
    except dns.resolver.NoNameservers: return [], "Nameserver unreachable"
    except dns.resolver.NoAnswer:
        try: r.resolve(domain, "A"); return [domain], "No MX; A-record fallback"
        except: return [], "No MX and no A-record"
    except Exception as e: return [], f"DNS error: {e}"

# ─────────────────────────────────────────────────────────────────────────────
# SIGNAL 3 — SPF record
# ─────────────────────────────────────────────────────────────────────────────
def check_spf(domain):
    if not HAS_DNS: return False, "DNS unavailable"
    r = dns.resolver.Resolver(); r.lifetime = DNS_TIMEOUT
    try:
        for rdata in r.resolve(domain, "TXT"):
            for s in rdata.strings:
                if b"v=spf1" in s:
                    return True, "SPF record found"
        return False, "No SPF record"
    except Exception:
        return False, "SPF lookup failed"

# ─────────────────────────────────────────────────────────────────────────────
# SIGNAL 4 — DMARC record
# ─────────────────────────────────────────────────────────────────────────────
def check_dmarc(domain):
    if not HAS_DNS: return False, "DNS unavailable"
    r = dns.resolver.Resolver(); r.lifetime = DNS_TIMEOUT
    try:
        for rdata in r.resolve(f"_dmarc.{domain}", "TXT"):
            for s in rdata.strings:
                if b"v=DMARC1" in s:
                    return True, "DMARC record found"
        return False, "No DMARC record"
    except Exception:
        return False, "DMARC lookup failed"

# ─────────────────────────────────────────────────────────────────────────────
# SIGNAL 5 — Gravatar (real person signal)
# ─────────────────────────────────────────────────────────────────────────────
def check_gravatar(email):
    try:
        h = hashlib.md5(email.strip().lower().encode()).hexdigest()
        r = requests.get(f"https://www.gravatar.com/avatar/{h}?d=404&s=1", timeout=5)
        if r.status_code == 200:
            return True, "Gravatar profile found (real person signal)"
        return False, "No Gravatar profile"
    except Exception:
        return False, "Gravatar check failed"

# ─────────────────────────────────────────────────────────────────────────────
# SIGNAL 6 — Catch-all + SMTP (works when port 25 is open)
# ─────────────────────────────────────────────────────────────────────────────
def smtp_probe(email, mx_hosts):
    """Returns (result, reason): result = True/False/None"""
    last = "No host tried"
    for host in mx_hosts[:2]:
        try:
            with smtplib.SMTP(timeout=SMTP_TIMEOUT) as s:
                s.connect(host, 25)
                s.ehlo_or_helo_if_needed()
                s.mail(SMTP_FROM)
                code, msg = s.rcpt(email)
                m = msg.decode(errors="replace") if isinstance(msg, bytes) else str(msg)
                if code in (250, 251): return True,  f"SMTP {code} accepted"
                if 550 <= code <= 559: return False, f"SMTP {code} rejected"
                last = f"SMTP {code}: {m[:50]}"
        except Exception as e:
            last = str(e)
        time.sleep(0.3)
    return None, f"Port 25 unreachable — {last}"

def check_catchall_and_smtp(email, domain, mx_hosts):
    """
    Step 1: probe a definitely-fake address on same domain
    Step 2: if server REJECTS fake → validates mailboxes → probe real address
            if server ACCEPTS fake → catch-all domain
    Returns (smtp_confirmed, is_catchall, reason)
    """
    fake  = f"xqzt7k2p9mzxw@{domain}"
    fake_result, _ = smtp_probe(fake, mx_hosts)

    if fake_result is None:
        # Port 25 blocked (cloud deployment) — SMTP unavailable
        return None, False, "SMTP unavailable (port 25 blocked)"

    if fake_result is True:
        # Server accepts everything — catch-all domain, can't verify individuals
        return None, True, "Catch-all domain — server accepts all addresses"

    # Server REJECTED the fake address — it validates mailboxes. Now probe real.
    real_result, real_reason = smtp_probe(email, mx_hosts)
    if real_result is True:
        return True, False, f"Confirmed: server rejected fake, accepted real — {real_reason}"
    if real_result is False:
        return False, False, f"Confirmed: server rejected this mailbox — {real_reason}"
    return None, False, f"SMTP inconclusive — {real_reason}"

# ─────────────────────────────────────────────────────────────────────────────
# SIGNAL 7 — Abstract API (optional)
# ─────────────────────────────────────────────────────────────────────────────
def verify_via_abstract(email, api_key):
    try:
        r = requests.get(
            "https://emailvalidation.abstractapi.com/v1/",
            params={"api_key": api_key, "email": email}, timeout=10
        )
        if r.status_code == 401: return None, "Invalid API key"
        if r.status_code == 429: return None, "Rate limit reached"
        if r.status_code != 200: return None, f"API error {r.status_code}"
        d = r.json()
        flags = []
        if d.get("is_disposable_email",{}).get("value"): flags.append("disposable")
        if d.get("is_role_email",      {}).get("value"): flags.append("role-based")
        if d.get("is_catchall_email",  {}).get("value"): flags.append("catch-all")
        if d.get("is_free_email",      {}).get("value"): flags.append("free provider")
        smtp_valid    = d.get("is_smtp_valid",  {}).get("value", False)
        mx_found      = d.get("is_mx_found",    {}).get("value", False)
        fmt_valid     = d.get("is_valid_format",{}).get("value", False)
        quality       = float(d.get("quality_score", 0))
        deliverability= d.get("deliverability","UNKNOWN").upper()
        note   = ", ".join(flags) if flags else "no flags"
        reason = (f"Abstract API · deliverability={deliverability} · "
                  f"quality={quality:.2f} · flags=[{note}]")
        if not fmt_valid:
            return dict(status="❌ Invalid Syntax",   score=0,   reason=reason), None
        if not mx_found:
            return dict(status="❌ Invalid Domain",   score=33,  reason=reason), None
        if d.get("is_disposable_email",{}).get("value"):
            return dict(status="❌ Disposable Email", score=10,  reason=reason), None
        if deliverability == "DELIVERABLE" and smtp_valid:
            return dict(status="✅ Valid",            score=100, reason=reason), None
        if deliverability == "UNDELIVERABLE":
            return dict(status="❌ Mailbox Not Found",score=40,  reason=reason), None
        if d.get("is_role_email",{}).get("value"):
            return dict(status="⚠️ Role-based",       score=55,  reason=reason), None
        return dict(status="⚠️ Unverified",           score=66,  reason=reason), None
    except Exception as e:
        return None, str(e)

# ─────────────────────────────────────────────────────────────────────────────
# MASTER CONFIDENCE ENGINE
# ─────────────────────────────────────────────────────────────────────────────
def verify(email, api_key=""):
    email = email.strip().lower()
    signals = {}

    # ── Syntax (gate) ──────────────────────────────────────────────────────
    ok, syn_reason = check_syntax(email)
    if not ok:
        return dict(email=email, status="❌ Invalid Syntax", score=0,
                    reason=syn_reason, signals={})
    local  = email.split("@")[0]
    domain = email.split("@")[1]

    # ── Abstract API (if key, skip everything else) ────────────────────────
    if api_key:
        result, err = verify_via_abstract(email, api_key)
        if result:
            result["email"]   = email
            result["signals"] = {"abstract_api": "✅ used"}
            return result

    # ── Disposable (gate) ─────────────────────────────────────────────────
    if domain in DISPOSABLE_DOMAINS:
        return dict(email=email, status="❌ Disposable Email", score=5,
                    reason=f"Known disposable domain: {domain}",
                    signals={"disposable": "❌ yes"})

    # ── DNS / MX (gate) ────────────────────────────────────────────────────
    mx_hosts, mx_reason = get_mx(domain)
    signals["mx"] = f"✅ {mx_reason}" if mx_hosts else f"❌ {mx_reason}"
    if not mx_hosts:
        return dict(email=email, status="❌ Invalid Domain", score=33,
                    reason=mx_reason, signals=signals)

    # ── Scoring engine ─────────────────────────────────────────────────────
    score = 40  # base: syntax + MX passed

    # SPF
    spf_ok, spf_reason = check_spf(domain)
    signals["spf"] = f"✅ {spf_reason}" if spf_ok else f"⚠️ {spf_reason}"
    if spf_ok: score += 10

    # DMARC
    dmarc_ok, dmarc_reason = check_dmarc(domain)
    signals["dmarc"] = f"✅ {dmarc_reason}" if dmarc_ok else f"⚠️ {dmarc_reason}"
    if dmarc_ok: score += 10

    # Role-based (penalty)
    is_role = local in ROLE_PREFIXES
    signals["role"] = "⚠️ role-based address" if is_role else "✅ personal address"
    if is_role: score -= 10

    # Free provider boost
    is_free = domain in FREE_PROVIDERS
    signals["provider"] = "✅ trusted free provider" if is_free else "✅ custom domain"
    if is_free: score += 10

    # Catch-all + SMTP (works locally; skipped on cloud)
    smtp_confirmed, is_catchall, smtp_reason = check_catchall_and_smtp(email, domain, mx_hosts)
    if smtp_confirmed is True:
        score = 100
        signals["smtp"] = f"✅ {smtp_reason}"
    elif smtp_confirmed is False:
        return dict(email=email, status="❌ Mailbox Not Found", score=35,
                    reason=smtp_reason, signals=signals)
    elif is_catchall:
        score += 10
        signals["smtp"] = f"⚠️ {smtp_reason}"
    else:
        signals["smtp"] = f"⚠️ {smtp_reason}"

    # Gravatar (real person signal)
    grav_ok, grav_reason = check_gravatar(email)
    signals["gravatar"] = f"✅ {grav_reason}" if grav_ok else f"⚠️ {grav_reason}"
    if grav_ok: score += 15

    # ── Final verdict ──────────────────────────────────────────────────────
    score = max(0, min(100, score))

    reason_parts = [mx_reason]
    if spf_ok:   reason_parts.append("SPF ✓")
    if dmarc_ok: reason_parts.append("DMARC ✓")
    if grav_ok:  reason_parts.append("Gravatar ✓")
    if is_catchall: reason_parts.append("catch-all domain")
    if is_role:  reason_parts.append("role-based")
    reason_parts.append(smtp_reason)
    reason = " · ".join(reason_parts)

    if score >= 80:
        status = "✅ Very Likely Valid"
    elif score >= 65:
        status = "✅ Likely Valid"
    elif score >= 45:
        status = "⚠️ Unverified"
    else:
        status = "⚠️ Low Confidence"

    return dict(email=email, status=status, score=score,
                reason=reason, signals=signals)

# ─────────────────────────────────────────────────────────────────────────────
# Render results
# ─────────────────────────────────────────────────────────────────────────────
def render_results(results):
    df = pd.DataFrame(results)[["email", "status", "score", "reason"]]
    total   = len(df)
    valid   = df["status"].str.contains("✅").sum()
    unver   = df["status"].str.contains("⚠️").sum()
    invalid = total - valid - unver

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total",          total)
    c2.metric("✅ Valid",        valid)
    c3.metric("⚠️ Unverified",  unver)
    c4.metric("❌ Invalid",      invalid)

    st.dataframe(df, use_container_width=True, height=min(500, 55 + len(df) * 38))

    # Signal breakdown for single email
    if len(results) == 1 and results[0].get("signals"):
        with st.expander("🔍 Signal Breakdown", expanded=True):
            for k, v in results[0]["signals"].items():
                st.markdown(f"**{k.upper()}** — {v}")

    csv_out = df.to_csv(index=False).encode("utf-8")
    st.download_button("⬇️ Download Results as CSV", csv_out,
                       "verified_results.csv", "text/csv")

# ─────────────────────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Settings")
    api_key = st.text_input(
        "Abstract API Key *(optional)*",
        type="password",
        placeholder="your_abstract_api_key",
        help="Get free key at abstractapi.com"
    )
    if api_key:
        st.success("✅ API key set — deep SMTP mode")
    else:
        st.info("Multi-signal mode (no key needed)")

    st.divider()
    st.markdown("**Active Signals**")
    st.markdown("✅ Syntax validation")
    st.markdown("✅ DNS / MX records")
    st.markdown("✅ Disposable detection")
    st.markdown("✅ Role-based detection")
    st.markdown("✅ SPF record check")
    st.markdown("✅ DMARC record check")
    st.markdown("✅ Catch-all detection")
    st.markdown("✅ Gravatar presence")
    st.markdown("✅ Provider trust boost")
    st.markdown(f"{'✅' if api_key else '⬜'} Abstract API (SMTP)")
    st.divider()
    st.caption("[Get free API key →](https://www.abstractapi.com/email-verification-validation-api)")

# ─────────────────────────────────────────────────────────────────────────────
# Main UI
# ─────────────────────────────────────────────────────────────────────────────
st.title("✉️ Email Verifier")
st.caption("9-signal confidence engine · Syntax · DNS · SPF · DMARC · Catch-all · Gravatar · SMTP")
st.divider()

tab_single, tab_bulk = st.tabs(["Single Email", "Bulk Verify"])

with tab_single:
    email_input = st.text_input("Enter an email address", placeholder="user@example.com")
    if st.button("Verify", type="primary", use_container_width=True):
        if not email_input.strip():
            st.warning("Please enter an email address.")
        else:
            with st.spinner("Running all checks…"):
                result = verify(email_input.strip(), api_key)
            render_results([result])

with tab_bulk:
    method = st.radio("How do you want to add emails?",
                      ["Upload CSV file", "Paste emails"], horizontal=True)
    emails = []

    if method == "Upload CSV file":
        uploaded = st.file_uploader("Upload a CSV with an **email** column", type=["csv"])
        if uploaded:
            df_in = pd.read_csv(uploaded)
            col = next((c for c in df_in.columns if c.strip().lower() == "email"), df_in.columns[0])
            emails = df_in[col].dropna().astype(str).str.strip().tolist()
            st.success(f"Loaded **{len(emails)}** email(s) from `{uploaded.name}`")
            st.dataframe(df_in[[col]].head(5), use_container_width=True)
    else:
        pasted = st.text_area("Paste emails — one per line",
                              placeholder="user@gmail.com\ntest@yahoo.com\ninvalid-email",
                              height=160)
        if pasted.strip():
            emails = [e.strip() for e in re.split(r"[\n,;]+", pasted) if e.strip()]
            st.caption(f"{len(emails)} email(s) detected")

    if st.button("Verify All", type="primary", use_container_width=True, disabled=len(emails) == 0):
        progress = st.progress(0, text="Starting…")
        results  = []
        for i, e in enumerate(emails):
            progress.progress((i + 1) / len(emails), text=f"Checking {i+1}/{len(emails)}: {e}")
            results.append(verify(e, api_key))
        progress.empty()
        render_results(results)
