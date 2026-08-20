#!/usr/bin/env python3
"""PMG mail statistics + SMTP reject-rate checks.

Section payload (JSON):
    {"mail": {...} | {"_error": ...},
     "rejectcount": [{"time":.., "rbl_rejects":.., "pregreet_rejects":..}, ...]
                     | {"_error": ...}}

"mail" comes from /statistics/mail (default: last 24h). "rejectcount" comes
from /statistics/rejectcount and is a list of time-bucketed samples (default:
hourly buckets over the last 24h) which we sum into 24h totals.
"""
import json
from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    Metric,
    Result,
    Service,
    State,
)


def parse_pmg_statistics(string_table):
    if not string_table:
        return {}
    try:
        return json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return {}


agent_section_pmg_statistics = AgentSection(
    name="pmg_statistics",
    parse_function=parse_pmg_statistics,
)


# --------------------------------------------------------------------------
# Mail throughput / junk ratio
# --------------------------------------------------------------------------
def discover_pmg_mail(section):
    mail = section.get("mail") if section else None
    if isinstance(mail, dict) and "_error" not in mail:
        yield Service()


def _levels(level_spec, default=(None, None)):
    """Unwrap a SimpleLevels-produced tagged tuple: ("fixed", (warn, crit))
    or ("no_levels", None). Falls back to treating an already-bare tuple
    as-is for back-compat with any pre-SimpleLevels stored value."""
    if isinstance(level_spec, tuple) and len(level_spec) == 2 and level_spec[0] in ("fixed", "no_levels"):
        kind, value = level_spec
        return value if kind == "fixed" else (None, None)
    if level_spec is None:
        return default
    return level_spec


def check_pmg_mail(params, section):
    mail = section.get("mail", {})
    if not isinstance(mail, dict) or "_error" in mail:
        yield Result(state=State.UNKNOWN,
                     summary="API error: %s" % mail.get("_error", "no data"))
        return

    count_in = float(mail.get("count_in", 0))
    count_out = float(mail.get("count_out", 0))
    count = float(mail.get("count", count_in + count_out))
    spam_in = float(mail.get("spamcount_in", 0))
    virus_in = float(mail.get("viruscount_in", 0))
    junk_in = float(mail.get("junk_in", 0))

    yield Result(state=State.OK,
                 summary="In: %d, Out: %d" % (int(count_in), int(count_out)))
    yield Metric("mail_count_in", count_in)
    yield Metric("mail_count_out", count_out)
    yield Metric("mail_count", count)

    spam_pct = (100.0 * spam_in / count_in) if count_in else 0.0
    virus_pct = (100.0 * virus_in / count_in) if count_in else 0.0
    junk_pct = (100.0 * junk_in / count_in) if count_in else 0.0

    warn, crit = _levels(params.get("junk_percent_levels", ("fixed", (50.0, 80.0))))
    state = State.OK
    if junk_pct >= crit:
        state = State.CRIT
    elif junk_pct >= warn:
        state = State.WARN
    yield Result(state=state,
                 summary="Junk ratio (in): %.1f%% (spam %.1f%%, virus %.1f%%)"
                 % (junk_pct, spam_pct, virus_pct))
    yield Metric("mail_junk_percent", junk_pct, levels=(warn, crit))

    spam_warn, spam_crit = _levels(params.get("spam_percent_levels", ("fixed", (30.0, 60.0))))
    spam_state = State.OK
    if spam_pct >= spam_crit:
        spam_state = State.CRIT
    elif spam_pct >= spam_warn:
        spam_state = State.WARN
    yield Result(state=spam_state,
                 summary="Spam ratio (in): %.1f%%" % spam_pct)
    yield Metric("mail_spam_percent", spam_pct, levels=(spam_warn, spam_crit))

    virus_warn, virus_crit = _levels(params.get("virus_percent_levels", ("fixed", (5.0, 20.0))))
    virus_state = State.OK
    if virus_pct >= virus_crit:
        virus_state = State.CRIT
    elif virus_pct >= virus_warn:
        virus_state = State.WARN
    yield Result(state=virus_state,
                 summary="Virus ratio (in): %.1f%%" % virus_pct)
    yield Metric("mail_virus_percent", virus_pct, levels=(virus_warn, virus_crit))

    avptime = mail.get("avptime")
    if avptime is not None:
        yield Result(state=State.OK,
                     summary="Avg. processing time: %.2fs" % float(avptime))
        yield Metric("mail_avptime", float(avptime))


check_plugin_pmg_mail = CheckPlugin(
    name="pmg_mail",
    sections=["pmg_statistics"],
    service_name="PMG Mail Statistics",
    discovery_function=discover_pmg_mail,
    check_function=check_pmg_mail,
    check_default_parameters={
        "junk_percent_levels": ("fixed", (50.0, 80.0)),
        "spam_percent_levels": ("fixed", (30.0, 60.0)),
        "virus_percent_levels": ("fixed", (5.0, 20.0)),
    },
    check_ruleset_name="pmg_mail",
)


# --------------------------------------------------------------------------
# SMTP early rejects (RBL / PREGREET)
# --------------------------------------------------------------------------
def discover_pmg_rejects(section):
    rc = section.get("rejectcount") if section else None
    if isinstance(rc, list):
        yield Service()


def check_pmg_rejects(params, section):
    rc = section.get("rejectcount")
    if isinstance(rc, dict) and "_error" in rc:
        yield Result(state=State.UNKNOWN, summary="API error: %s" % rc["_error"])
        return
    if not isinstance(rc, list):
        yield Result(state=State.UNKNOWN, summary="No reject data")
        return

    rbl = sum(int(e.get("rbl_rejects", 0)) for e in rc if isinstance(e, dict))
    pregreet = sum(int(e.get("pregreet_rejects", 0)) for e in rc if isinstance(e, dict))
    total = rbl + pregreet

    warn, crit = _levels(params.get("levels", ("no_levels", None)))
    state = State.OK
    if crit is not None and total >= crit:
        state = State.CRIT
    elif warn is not None and total >= warn:
        state = State.WARN

    yield Result(state=state,
                 summary="RBL: %d, PREGREET: %d (total %d over reporting window)"
                 % (rbl, pregreet, total))
    yield Metric("pmg_rbl_rejects", rbl)
    yield Metric("pmg_pregreet_rejects", pregreet)
    yield Metric("pmg_rejects_total", total,
                 levels=(warn, crit) if warn is not None else None)


check_plugin_pmg_rejects = CheckPlugin(
    name="pmg_rejects",
    sections=["pmg_statistics"],
    service_name="PMG SMTP Rejects",
    discovery_function=discover_pmg_rejects,
    check_function=check_pmg_rejects,
    check_default_parameters={"levels": ("no_levels", None)},
    check_ruleset_name="pmg_rejects",
)
