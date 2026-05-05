"""
Email Verification Dashboard — Streamlit
Deploy free at: https://streamlit.io/cloud
"""

import csv
import io
import re
import smtplib
import socket
import time

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
st.set_page_config(
    page_title="Email Verifier",
    page_icon="✉️",
    layout="centered",
)

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
# Verification logic
# ─────────────────────────────────────────────────────────────────────────────
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
SMTP_TIMEOUT = 10
SMTP_FROM    = "verify@verification-check.local"
DNS_TIMEOUT  = 5

def check_syntax(email):
    if not email: return False, "Empty address"
    if email.count("@") != 1:
        return False, f"Invalid — {email.count('@')} '@' characters"
    local, domain = email.split("@", 1)
    if not local: return False, "Missing local part (before @)"
    if not domain or "." not in domain: return False, "Domain missing or has no TLD"
    if not _EMAIL_RE.match(email): return False, "Fails RFC-5321 syntax check"
    return True, "Syntax OK"

def get_mx(domain):
    if not HAS_DNS:
        try:
            socket.setdefaulttimeout(DNS_TIMEOUT)
            socket.gethostbyname(domain)
            return [domain], "A-record found"
        except socket.gaierror as e:
            return [], str(e)
    r = dns.resolver.Resolver(); r.lifetime = DNS_TIMEOUT
    try:
        ans = r.resolve(domain, "MX")
        hosts = [str(a.exchange).rstrip(".") for a in sorted(ans, key=lambda x: x.preference)]
        return hosts, f"{len(hosts)} MX record(s) found"
    except dns.resolver.NXDOMAIN: return [], "Domain does not exist (NXDOMAIN)"
    except dns.resolver.NoNameservers: return [], "Nameserver unreachable"
    except dns.resolver.NoAnswer:
        try: r.resolve(domain, "A"); return [domain], "No MX; A-record fallback used"
        except: return [], "No MX and no A-record found"
    except Exception as e: return [], f"DNS error: {e}"

def check_smtp(email, mx_hosts):
    last = "No host tried"
    for host in mx_hosts[:2]:
        try:
            with smtplib.SMTP(timeout=SMTP_TIMEOUT) as s:
                s.connect(host, 25)
                s.ehlo_or_helo_if_needed()
                s.mail(SMTP_FROM)
                code, msg = s.rcpt(email)
                m = msg.decode(errors="replace") if isinstance(msg, bytes) else str(msg)
                if code in (250, 251): return True,  f"SMTP {code} OK — accepted by {host}"
                if code in range(550, 556): return False, f"SMTP {code} — mailbox rejected by {host}"
                last = f"SMTP {code} from {host}: {m[:60]}"
        except Exception as e:
            last = str(e)
        time.sleep(0.5)
    return None, f"SMTP inconclusive — {last}"

def verify(email):
    email = email.strip().lower()
    ok, reason = check_syntax(email)
    if not ok:
        return dict(email=email, status="❌ Invalid Syntax",  score=0,   reason=reason)
    domain = email.split("@")[1]
    mx, dns_reason = get_mx(domain)
    if not mx:
        return dict(email=email, status="❌ Invalid Domain", score=33,  reason=dns_reason)
    smtp_ok, smtp_reason = check_smtp(email, mx)
    reason = f"{dns_reason} · {smtp_reason}"
    if smtp_ok is True:  return dict(email=email, status="✅ Valid",           score=100, reason=reason)
    if smtp_ok is False: return dict(email=email, status="❌ Mailbox Not Found", score=66, reason=reason)
    return dict(email=email, status="⚠️ Unverified", score=66, reason=reason)

# ─────────────────────────────────────────────────────────────────────────────
# Helper — colour the Status column
# ─────────────────────────────────────────────────────────────────────────────
def render_results(results):
    df = pd.DataFrame(results)[["email","status","score","reason"]]
    total   = len(df)
    valid   = (df["status"].str.contains("✅")).sum()
    unver   = (df["status"].str.contains("⚠️")).sum()
    invalid = total - valid - unver

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total",        total)
    c2.metric("✅ Valid",      valid)
    c3.metric("⚠️ Unverified", unver)
    c4.metric("❌ Invalid",    invalid)

    st.dataframe(df, use_container_width=True, height=min(400, 50 + len(df) * 38))

    csv_out = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="⬇️ Download Results as CSV",
        data=csv_out,
        file_name="verified_results.csv",
        mime="text/csv",
    )

# ─────────────────────────────────────────────────────────────────────────────
# UI
# ─────────────────────────────────────────────────────────────────────────────
st.title("✉️ Email Verifier")
st.caption("Checks Syntax · DNS / MX Records · SMTP Mailbox — no emails are sent")
st.divider()

tab_single, tab_bulk = st.tabs(["Single Email", "Bulk Verify"])

# ── Single ────────────────────────────────────────────────────────────────────
with tab_single:
    email_input = st.text_input(
        "Enter an email address",
        placeholder="user@example.com",
    )
    if st.button("Verify", type="primary", use_container_width=True):
        if not email_input.strip():
            st.warning("Please enter an email address.")
        else:
            with st.spinner("Checking…"):
                result = verify(email_input.strip())
            render_results([result])

# ── Bulk ──────────────────────────────────────────────────────────────────────
with tab_bulk:
    method = st.radio(
        "How do you want to add emails?",
        ["Upload CSV file", "Paste emails"],
        horizontal=True,
    )

    emails = []

    if method == "Upload CSV file":
        uploaded = st.file_uploader(
            "Upload a CSV with an **email** column",
            type=["csv"],
        )
        if uploaded:
            df_in = pd.read_csv(uploaded)
            col = next((c for c in df_in.columns if c.strip().lower() == "email"), df_in.columns[0])
            emails = df_in[col].dropna().astype(str).str.strip().tolist()
            st.success(f"Loaded **{len(emails)}** email(s) from `{uploaded.name}`")
            st.dataframe(df_in[[col]].head(5), use_container_width=True)

    else:
        pasted = st.text_area(
            "Paste emails — one per line",
            placeholder="user@gmail.com\ntest@yahoo.com\ninvalid-email",
            height=160,
        )
        if pasted.strip():
            emails = [e.strip() for e in re.split(r"[\n,;]+", pasted) if e.strip()]
            st.caption(f"{len(emails)} email(s) detected")

    if st.button("Verify All", type="primary", use_container_width=True, disabled=len(emails)==0):
        progress = st.progress(0, text="Starting…")
        results  = []
        for i, e in enumerate(emails):
            progress.progress((i + 1) / len(emails), text=f"Checking {i+1}/{len(emails)}: {e}")
            results.append(verify(e))
        progress.empty()
        render_results(results)
