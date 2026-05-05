"""
Email Verification Dashboard — Streamlit
Levels: Syntax → DNS/MX → Disposable/Role → Abstract API (SMTP + deep checks)
"""

import re
import time
import socket
import smtplib

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
# LEVEL 2 — Disposable & Role-based lists
# ─────────────────────────────────────────────────────────────────────────────
DISPOSABLE_DOMAINS = {
    "mailinator.com","guerrillamail.com","guerrillamail.net","guerrillamail.org",
    "guerrillamail.biz","guerrillamail.de","guerrillamail.info","guerrillamail.mobi",
    "sharklasers.com","guerrillamailblock.com","grr.la","guerrillamail.io",
    "tempmail.com","temp-mail.org","throwam.com","trashmail.com","trashmail.at",
    "trashmail.io","trashmail.me","trashmail.net","dispostable.com",
    "yopmail.com","yopmail.fr","cool.fr.nf","jetable.fr.nf","nospam.ze.tc",
    "nomail.xl.cx","mega.zik.dj","speed.1s.fr","courriel.fr.nf","moncourrier.fr.nf",
    "monemail.fr.nf","monmail.fr.nf","fakeinbox.com","mailnull.com","spamgourmet.com",
    "spamgourmet.net","spamgourmet.org","spamgourmet.me","10minutemail.com",
    "10minutemail.net","10minutemail.org","10minutemail.de","10minutemail.co.za",
    "20minutemail.com","throwam.com","throwam.net","maildrop.cc","discard.email",
    "spamfree24.org","spamfree24.de","spamfree24.eu","spamfree24.info",
    "spamfree24.net","spam4.me","binkmail.com","bob.email","clrmail.com",
    "crapmail.org","dayrep.com","deadaddress.com","deadletter.ga","dispostable.com",
    "dm.w3internet.co.uk","dodgeit.com","dodgit.com","donemail.ru","dontreg.com",
    "dontsendmespam.de","drdrb.com","dump-email.info","dumpandfuck.com",
    "dumpmail.de","dumpyemail.com","e4ward.com","emailgo.de","emailias.com",
    "emailinfive.com","emailisvalid.com","emailmiser.com","emailsensei.com",
    "emailtemporanea.com","emailtemporanea.net","emailtemporario.com.br",
    "emailthe.net","emailtmp.com","emailwarden.com","emailx.at.hm",
    "emailxfer.com","emailz.cf","emailz.ga","emailz.gq","emailz.ml",
    "emkei.cz","emkei.ga","emkei.gq","emkei.ml","emkei.tk",
    "fakedemail.com","fakemailz.com","fastacura.com","fastem.com",
    "fastemailer.com","faster-mail.org","fastimap.com","fastmazda.com",
    "fastmitsubishi.com","fastnissan.com","fastsubaru.com","fastsuzuki.com",
    "fasttoyota.com","fastyamaha.com","filzmail.com","fizmail.com",
    "fleckens.hu","flurre.com","flurred.com","flyspam.com","frapmail.com",
    "freundin.ru","fuckingduh.com","fudgerub.com","garliclife.com",
    "get2mail.fr","getairmail.com","getmails.eu","getonemail.com",
    "giantmail.de","girlsundertheinfluence.com","gishpuppy.com","gowikibooks.com",
    "gowikicampus.com","gowikicars.com","gowikifilms.com","gowikigames.com",
    "gowikimusic.com","gowikinetwork.com","gowikitravel.com","gowikitv.com",
    "grandmamail.com","grandmasmail.com","great-host.in","greensloth.com",
    "hamham.uk","hat-geld.de","herp.in","hmamail.com","hotemails.net",
    "humaility.com","ieatspam.eu","ieatspam.info","ieh-mail.de","ignoremail.com",
    "ihateyoualot.info","iheartspam.org","imails.info","inboxalias.com",
    "incognitomail.com","incognitomail.net","incognitomail.org","ineednewshoes.com",
    "inoutmail.de","inoutmail.eu","inoutmail.info","inoutmail.net",
    "insorg-mail.info","instant-mail.de","internet-e-mail.de","internet-mail.org",
    "internetemails.net","internetmailing.net","inwind.it","iozak.com",
    "irish2me.com","jetable.com","jetable.de","jetable.eu","jetable.fr.nf",
    "jetable.net","jetable.org","jnxjn.com","jnxjn.net","jourrapide.com",
    "jsrsolutions.com","junk.to","junkmail.ga","junkmail.gq","jupimail.com",
    "kasmail.com","kaspop.com","keepmymail.com","killmail.com","killmail.net",
    "kir.ch.tc","klassmaster.com","klassmaster.net","klzlk.com","koszmail.pl",
    "kurzepost.de","letthemeatspam.com","lhsdv.com","libox.fr","lifebyfood.com",
    "link2mail.net","litedrop.com","lol.ovpn.to","lolfreak.net","lookugly.com",
    "lortemail.dk","lukemail.com","lump.com","maboard.com","mail-filter.com",
    "mail-temp.com","mail.by","mail.mezimages.net","mail333.com","mailbidon.com",
    "mailbiz.biz","mailblocks.com","mailbucket.org","mailcat.biz","mailcatch.com",
    "mailde.de","mailde.info","maildrop.cc","mailexpire.com","mailfa.tk",
    "mailforspam.com","mailfreeonline.com","mailguard.me","mailhazard.com",
    "mailhazard.us","mailimelt.info","mailimate.com","mailin8r.com","mailinater.com",
    "mailinator.net","mailinator.org","mailinator.gq","mailinator2.com",
    "mailincubator.com","mailismagic.com","mailjunk.cf","mailjunk.ga",
    "mailjunk.gq","mailjunk.ml","mailjunk.tk","mailmate.com","mailme.ir",
    "mailme.lv","mailme24.com","mailmetrash.com","mailmoat.com","mailnew.com",
    "mailnull.com","mailorg.org","mailpick.biz","mailproxsy.com","mailquack.com",
    "mailsac.com","mailscrap.com","mailshell.com","mailsiphon.com","mailslapping.com",
    "mailslite.com","mailspam.me","mailspam.xyz","mailsucker.net","mailtemporal.com",
    "mailtemporaire.com","mailtemporaire.fr","mailtome.de","mailtothis.com",
    "mailtrash.net","mailtrix.net","mailtv.net","mailzilla.com","mailzilla.org",
    "mbx.cc","mega.zik.dj","meinspamschutz.de","meltmail.com","messagebeamer.de",
    "mezimages.net","mierdamail.com","migumail.com","mintemail.com","moburl.com",
    "moncourrier.fr.nf","monemail.fr.nf","monmail.fr.nf","msa.minsmail.com",
    "mt2009.com","mt2014.com","mx0.wwwnew.eu","mymail-in.net","mymailoasis.com",
    "mypartyclip.de","myphantomemail.com","mysamp.de","myspamless.com",
    "mytempemail.com","mytempmail.com","mytrashmail.com","nabuma.com",
    "neomailbox.com","nepwk.com","nervmich.net","nervtmich.net","netmails.com",
    "netmails.net","netzidiot.de","neuf.fr","neutralize.it","newbpotato.tk",
    "nice-4u.com","nincsmail.com","nmail.cf","no-spam.ws","nobulk.com",
    "noclickemail.com","nogmailspam.info","nomail.pw","nomail.xl.cx",
    "nomail2me.com","nomorespamemails.com","nonspam.eu","nonspammer.de",
    "noref.in","noreplyx.com","nospam.ze.tc","nospam4.us","nospamfor.us",
    "nospammail.net","nospamthanks.info","notmailinator.com","notsharingmy.info",
    "nowhere.org","nowmymail.com","nwldx.com","objectmail.com","obobbo.com",
    "odaymail.com","oe788.com","ohaaa.de","omail.pro","onewaymail.com",
    "onlatedotcom.info","online.ms","opayq.com","opentrash.com","ordinaryamerican.net",
    "otherinbox.com","ourklips.com","outlawspam.com","ovpn.to","owlpic.com",
    "pancakemail.com","paplease.com","pcusers.otherinbox.com","pepbot.com",
    "pfui.ru","pimpedupmyspace.com","pisosation.com","planet-inter.net",
    "pleasenomail.com","politikerclub.de","pookmail.com","postalmail.biz",
    "powered.name","privacy.net","proxymail.eu","prtnx.com","prtz.eu",
    "punkass.com","put2.net","pwrby.com","quickinbox.com","quickmail.nl",
    "rcpt.at","reallymymail.com","recode.me","recyclemail.dk","regbypass.com",
    "regbypass.comsafe-mail.net","safetypost.de","sandelf.de","saynotospams.com",
    "selfdestructingmail.com","selfdestructingmail.org","sendspamhere.com",
    "sharedmailbox.org","sharklasers.com","shieldemail.com","shiftmail.com",
    "shitmail.de","shitmail.me","shitware.nl","shmeriously.com","shortmail.net",
    "sibmail.com","sinnlos-mail.de","skeefmail.com","slapsfromlastnight.com",
    "slaskpost.se","slopsbox.com","smellfear.com","smwg.info","snakemail.com",
    "sneakemail.com","sneakmail.de","snkmail.com","sofimail.com","sofort-mail.de",
    "sogetthis.com","solopilotos.com","soodonims.com","spam.la","spam.su",
    "spam4.me","spamavert.com","spambob.com","spambob.net","spambob.org",
    "spambog.com","spambog.de","spambog.ru","spambox.info","spambox.irishspringrealty.com",
    "spambox.us","spamcannon.com","spamcannon.net","spamcero.com","spamcon.org",
    "spamcorptastic.com","spamcowboy.com","spamcowboy.net","spamcowboy.org",
    "spamday.com","spamex.com","spamfree.eu","spamfree24.de","spamfree24.eu",
    "spamfree24.info","spamfree24.net","spamfree24.org","spamgoes.in",
    "spamgourmet.com","spamgourmet.net","spamgourmet.org","spamherelots.com",
    "spamherelots.com","spamhereplease.com","spamhereplease.com","spamhole.com",
    "spamify.com","spaminator.de","spamkill.info","spaml.com","spaml.de",
    "spammotel.com","spammy.host","spamoff.de","spamsalad.in","spamslicer.com",
    "spamspot.com","spamstack.net","spamthis.co.uk","spamthisplease.com",
    "spamtroll.net","spamwc.cf","spamwc.de","spamwc.ga","spamwc.gq",
    "spamwc.ml","speakfreely.email","speed.1s.fr","spoofmail.de","squizzy.de",
    "squizzy.eu","squizzy.net","stinkefinger.net","stuffmail.de","super-auswahl.de",
    "supergreatmail.com","supermailer.jp","superrito.com","superstachel.de",
    "suremail.info","tafmail.com","tagyourself.com","talkinator.com",
    "tapchief.com","tefl.ro","teleworm.com","teleworm.us","temp-mail.com",
    "temp-mail.de","temp-mail.org","temp-mail.ru","temp.bartdevos.be",
    "temp.emeraldwebmail.com","temp.headstrong.de","temp.mail.y59.jp",
    "tempail.com","tempalias.com","tempe-mail.com","tempemail.biz","tempemail.com",
    "tempemail.co.za","tempemail.net","tempemail.org","tempimbox.com",
    "tempinbox.com","tempinbox.co.uk","tempmail.com","tempmail.de",
    "tempmail.eu","tempmail.it","tempmail.net","tempmail.org","tempmail.us",
    "tempmail2.com","tempomail.fr","temporaryemail.com","temporaryemail.net",
    "temporaryforwarding.com","temporaryinbox.com","temporarymail.org",
    "tempr.email","tempsky.com","tempthe.net","tempymail.com","thanksnospam.info",
    "thecloudindex.com","thisisnotmyrealemail.com","thismail.net","thismail.ru",
    "throwam.com","throwam.net","throwaway.email","throwaways.ml","throwmail.com",
    "tidni.com","tmail.com","tmail.io","tmailinator.com","toiea.com",
    "tokenmail.de","toomail.biz","topranklist.de","tradermail.info","trash-amil.com",
    "trash-mail.at","trash-mail.com","trash-mail.de","trash-mail.ga","trash-mail.gq",
    "trash-mail.ml","trash-mail.tk","trash2009.com","trash2010.com","trash2011.com",
    "trashcanmail.com","trashdevil.com","trashdevil.de","trashemail.de",
    "trashinbox.com","trashmail.app","trashmail.at","trashmail.com",
    "trashmail.de","trashmail.ga","trashmail.gq","trashmail.io","trashmail.me",
    "trashmail.ml","trashmail.net","trashmail.org","trashmail.tk","trashmail.xyz",
    "trashmailer.com","trashmails.com","trashspam.com","trbvm.com",
    "trbvn.com","trialmail.de","trickmail.net","trillianpro.com","trnksmail.se",
    "troll.com","tryalert.com","turual.com","twinmail.de","tyldd.com",
    "uggsrock.com","umail.net","unids.com","upliftnow.com","uplipht.com",
    "uroid.com","us.af","usermail.com","utiket.us","vaasfc4.tk",
    "vaultmail.com","veryrealemail.com","vidchart.com","viditag.com",
    "viewcastmedia.com","viewcastmedia.net","viewcastmedia.org","viralplays.com",
    "vkcode.ru","vmailing.info","vmani.com","vomoto.com","vpn.st",
    "vsimcard.com","vubby.com","walala.org","walkmail.net","walkmail.ru",
    "webemail.me","weg-werf-email.de","wegwerf-email-addressen.de",
    "wegwerf-emails.de","wegwerfadresse.de","wegwerfemail.com","wegwerfemail.de",
    "wegwerfmail.de","wegwerfmail.info","wegwerfmail.net","wegwerfmail.org",
    "wegwerfmailadresse.de","wetrainbayarea.com","wetrainbayarea.org",
    "wh4f.org","whopy.com","whyspam.me","wilemail.com","willhackforfood.biz",
    "willselfdestruct.com","winemaven.info","wronghead.com","wuzupmail.net",
    "xagloo.co","xagloo.com","xemaps.com","xents.com","xmail.pw","xmaily.com",
    "xoxy.net","xyzfree.net","yapped.net","yeah.net","yep.it",
    "yogamaven.com","yopmail.com","yopmail.fr","yourdomain.com","ypmail.webarnak.fr.eu.org",
    "yuurok.com","z1p.biz","za.com","zehnminuten.de","zehnminutenmail.de",
    "zippymail.info","zoemail.com","zoemail.net","zoemail.org","zomg.info",
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

# ─────────────────────────────────────────────────────────────────────────────
# LEVEL 1 — Syntax
# ─────────────────────────────────────────────────────────────────────────────
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
DNS_TIMEOUT = 5

def check_syntax(email):
    if not email: return False, "Empty address"
    if email.count("@") != 1:
        return False, f"Invalid — {email.count('@')} '@' characters found"
    local, domain = email.split("@", 1)
    if not local: return False, "Missing local part (before @)"
    if not domain or "." not in domain: return False, "Domain missing or has no TLD"
    if not _EMAIL_RE.match(email): return False, "Fails RFC-5321 syntax check"
    return True, "Syntax OK"

# ─────────────────────────────────────────────────────────────────────────────
# LEVEL 2 — DNS/MX + Disposable + Role
# ─────────────────────────────────────────────────────────────────────────────
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

def check_disposable(domain):
    if domain.lower() in DISPOSABLE_DOMAINS:
        return True, f"Disposable/temporary email domain ({domain})"
    return False, ""

def check_role(local):
    if local.lower() in ROLE_PREFIXES:
        return True, f"Role-based address ('{local}') — not a personal inbox"
    return False, ""

# ─────────────────────────────────────────────────────────────────────────────
# LEVEL 3 — Abstract API
# ─────────────────────────────────────────────────────────────────────────────
def verify_via_abstract(email, api_key):
    try:
        url = "https://emailvalidation.abstractapi.com/v1/"
        r = requests.get(url, params={"api_key": api_key, "email": email}, timeout=10)
        if r.status_code == 401:
            return None, "Invalid API key"
        if r.status_code == 429:
            return None, "API rate limit reached — try again later"
        if r.status_code != 200:
            return None, f"API error {r.status_code}"
        d = r.json()

        # Build a human-readable reason
        flags = []
        if d.get("is_disposable_email", {}).get("value"): flags.append("disposable")
        if d.get("is_role_email",       {}).get("value"): flags.append("role-based")
        if d.get("is_catchall_email",   {}).get("value"): flags.append("catch-all domain")
        if d.get("is_free_email",       {}).get("value"): flags.append("free provider")

        smtp_valid  = d.get("is_smtp_valid",  {}).get("value", False)
        mx_found    = d.get("is_mx_found",    {}).get("value", False)
        fmt_valid   = d.get("is_valid_format",{}).get("value", False)
        quality     = float(d.get("quality_score", 0))

        deliverability = d.get("deliverability", "UNKNOWN").upper()

        note = ", ".join(flags) if flags else "no flags"
        reason = (f"Abstract API · deliverability={deliverability} · "
                  f"quality={quality:.2f} · flags=[{note}] · "
                  f"mx={mx_found} · smtp={smtp_valid}")

        if not fmt_valid:
            return dict(status="❌ Invalid Syntax",  score=0,  reason=reason)
        if not mx_found:
            return dict(status="❌ Invalid Domain",  score=33, reason=reason)
        if d.get("is_disposable_email", {}).get("value"):
            return dict(status="❌ Disposable Email", score=20, reason=reason)
        if deliverability == "DELIVERABLE" and smtp_valid:
            return dict(status="✅ Valid",            score=100, reason=reason)
        if deliverability == "UNDELIVERABLE":
            return dict(status="❌ Mailbox Not Found",score=40,  reason=reason)
        if d.get("is_role_email", {}).get("value"):
            return dict(status="⚠️ Role-based",       score=55,  reason=reason)
        return dict(status="⚠️ Unverified",           score=66,  reason=reason)

    except requests.exceptions.Timeout:
        return None, "Abstract API timed out"
    except Exception as e:
        return None, f"Abstract API error: {e}"

# ─────────────────────────────────────────────────────────────────────────────
# Master verify function
# ─────────────────────────────────────────────────────────────────────────────
def verify(email, api_key=""):
    email = email.strip().lower()

    # Level 1 — Syntax
    ok, reason = check_syntax(email)
    if not ok:
        return dict(email=email, status="❌ Invalid Syntax", score=0, reason=reason)

    local  = email.split("@")[0]
    domain = email.split("@")[1]

    # Level 3 — Abstract API (if key provided, skip lower levels)
    if api_key:
        result, err = verify_via_abstract(email, api_key)
        if result is not None:
            result["email"] = email
            return result
        # API failed — fall through to local checks
        api_note = f" [API unavailable: {err}]"
    else:
        api_note = ""

    # Level 2 — Disposable check
    is_disp, disp_reason = check_disposable(domain)
    if is_disp:
        return dict(email=email, status="❌ Disposable Email", score=20,
                    reason=disp_reason + api_note)

    # Level 2 — Role-based check
    is_role, role_reason = check_role(local)

    # Level 1.5 — DNS/MX
    mx, dns_reason = get_mx(domain)
    if not mx:
        return dict(email=email, status="❌ Invalid Domain", score=33,
                    reason=dns_reason + api_note)

    if is_role:
        return dict(email=email, status="⚠️ Role-based", score=55,
                    reason=f"{dns_reason} · {role_reason}" + api_note)

    return dict(email=email, status="⚠️ Unverified", score=66,
                reason=f"{dns_reason} · SMTP probe not available from cloud" + api_note)

# ─────────────────────────────────────────────────────────────────────────────
# Render results table
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

    csv_out = df.to_csv(index=False).encode("utf-8")
    st.download_button("⬇️ Download Results as CSV", csv_out,
                       "verified_results.csv", "text/csv")

# ─────────────────────────────────────────────────────────────────────────────
# Sidebar — API Key
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Settings")
    st.markdown("**Abstract API Key** *(optional)*")
    api_key = st.text_input(
        "Paste your key here",
        type="password",
        placeholder="your_abstract_api_key",
        help="Get a free key at abstractapi.com — enables deep SMTP verification"
    )
    if api_key:
        st.success("✅ API key set — using deep verification")
    else:
        st.info("No API key — using Syntax + DNS + Disposable checks")

    st.divider()
    st.markdown("**Verification Levels**")
    st.markdown("✅ **Level 1** — Syntax (always on)")
    st.markdown("✅ **Level 2** — DNS/MX + Disposable + Role (always on)")
    st.markdown(f"{'✅' if api_key else '⬜'} **Level 3** — SMTP via Abstract API")
    st.divider()
    st.caption("Get a free API key → [abstractapi.com](https://www.abstractapi.com/email-verification-validation-api)")

# ─────────────────────────────────────────────────────────────────────────────
# Main UI
# ─────────────────────────────────────────────────────────────────────────────
st.title("✉️ Email Verifier")
st.caption("Syntax · DNS/MX · Disposable · Role-based · SMTP (with API key)")
st.divider()

tab_single, tab_bulk = st.tabs(["Single Email", "Bulk Verify"])

# ── Single ────────────────────────────────────────────────────────────────────
with tab_single:
    email_input = st.text_input("Enter an email address", placeholder="user@example.com")
    if st.button("Verify", type="primary", use_container_width=True):
        if not email_input.strip():
            st.warning("Please enter an email address.")
        else:
            with st.spinner("Checking…"):
                result = verify(email_input.strip(), api_key)
            render_results([result])

# ── Bulk ──────────────────────────────────────────────────────────────────────
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
