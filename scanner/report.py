"""
Generate a client-style PDF assessment report from scanner output.

Usage:
    python3 report.py                                   # reads findings.json
    python3 report.py --findings findings.json \\
                      --engagement ../engagement.json \\
                      --accepted ../accepted_risks.json \\
                      --out ../report/assessment-report.pdf
"""

import argparse
import json
import os
from collections import Counter, OrderedDict
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether, NextPageTemplate,
                                PageBreak, PageTemplate, Paragraph, Spacer, Table,
                                TableStyle)

from mappings import CONTROLS, DORA_ARTICLES, RATING_BANDS

# ---------------------------------------------------------------- palette
NAVY = colors.HexColor("#1B3A6B")
TEAL = colors.HexColor("#1A6E7E")
INK = colors.HexColor("#2B2B2B")
MUTED = colors.HexColor("#6B6B6B")
RULE = colors.HexColor("#D5DCE6")
PANEL = colors.HexColor("#F2F5F9")

SEVERITY_COLOUR = {
    "Critical": colors.HexColor("#8E1B1B"),
    "High": colors.HexColor("#C2571A"),
    "Medium": colors.HexColor("#B8860B"),
    "Low": colors.HexColor("#5A7A5A"),
}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
TIMEFRAME = {"Critical": "Immediate", "High": "Within 30 days",
             "Medium": "Within 90 days", "Low": "Next review cycle"}

# DORA Chapter II articles, for the coverage section
CHAPTER_II = OrderedDict([
    ("Art. 5", "Governance and organisation"),
    ("Art. 6", "ICT risk management framework"),
    ("Art. 7", "ICT systems, protocols and tools"),
    ("Art. 8", "Identification"),
    ("Art. 9", "Protection and prevention"),
    ("Art. 10", "Detection"),
    ("Art. 11", "Response and recovery"),
    ("Art. 12", "Backup policies and procedures, restoration and recovery"),
    ("Art. 13", "Learning and evolving"),
    ("Art. 14", "Communication"),
])

# ---------------------------------------------------------------- styles
def S(name, **kw):
    base = dict(fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=INK,
                alignment=TA_LEFT)
    base.update(kw)
    return ParagraphStyle(name, **base)

STY = {
    "h1": S("h1", fontName="Helvetica-Bold", fontSize=16, leading=20, textColor=NAVY,
            spaceBefore=4, spaceAfter=8),
    "h2": S("h2", fontName="Helvetica-Bold", fontSize=11.5, leading=15, textColor=NAVY,
            spaceBefore=10, spaceAfter=4),
    "body": S("body", spaceAfter=6),
    "small": S("small", fontSize=8.5, leading=11.5, textColor=MUTED),
    "cell": S("cell", fontSize=8.5, leading=11),
    "cellb": S("cellb", fontName="Helvetica-Bold", fontSize=8.5, leading=11),
    "head": S("head", fontName="Helvetica-Bold", fontSize=8.5, leading=11,
              textColor=colors.white),
    "bullet": S("bullet", leftIndent=12, bulletIndent=2, spaceAfter=3),
    "label": S("label", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=MUTED),
}


def p(text, style="body"):
    return Paragraph(text, STY[style])


def esc(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def badge(severity, score=None):
    colour = SEVERITY_COLOUR[severity].hexval()[2:]
    label = f"{severity} ({score})" if score is not None else severity
    return Paragraph(f'<font color="#{colour}"><b>{label}</b></font>', STY["cell"])


def grid_table(rows, widths, header=True, zebra=True):
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), NAVY)]
    if zebra:
        for i in range(1 if header else 0, len(rows)):
            if i % 2 == 0:
                style.append(("BACKGROUND", (0, i), (-1, i), PANEL))
    t.setStyle(TableStyle(style))
    return t


# ---------------------------------------------------------------- page furniture
def make_doc(path, eng, generated):
    doc = BaseDocTemplate(path, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
                          topMargin=22 * mm, bottomMargin=20 * mm,
                          title=f"{eng['report_title']} - {eng['entity']}",
                          author=eng["assessor"])
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="f")

    def cover(c, d):
        w, h = A4
        c.saveState()
        c.setFillColor(NAVY)
        c.rect(0, h - 95 * mm, w, 95 * mm, stroke=0, fill=1)
        c.setFillColor(colors.white)
        c.setFont("Helvetica", 10)
        c.drawString(20 * mm, h - 25 * mm, "DORA CHAPTER II  |  ICT RISK MANAGEMENT")
        c.setFont("Helvetica-Bold", 26)
        c.drawString(20 * mm, h - 48 * mm, eng["report_title"])
        c.setFont("Helvetica", 13)
        c.drawString(20 * mm, h - 58 * mm, eng["subtitle"])
        c.setFont("Helvetica-Bold", 14)
        c.drawString(20 * mm, h - 80 * mm, eng["entity"])

        c.setFillColor(colors.HexColor("#FFF4E5"))
        c.setStrokeColor(colors.HexColor("#C2571A"))
        c.rect(20 * mm, h - 128 * mm, w - 40 * mm, 20 * mm, stroke=1, fill=1)
        c.setFillColor(colors.HexColor("#7A3410"))
        c.setFont("Helvetica-Bold", 9.5)
        c.drawString(25 * mm, h - 116 * mm, "FICTIONAL ENTITY  -  LAB EXERCISE")
        c.setFont("Helvetica", 8.5)
        c.drawString(25 * mm, h - 122.5 * mm,
                     "Prepared against a purpose-built test environment. Any resemblance to a real "
                     "organisation is coincidental.")

        c.setFillColor(INK)
        y = h - 150 * mm
        for label, value in (("Prepared by", eng["assessor"]),
                             ("Assessment date", generated),
                             ("Report version", eng["version"]),
                             ("Classification", "Public - sample deliverable")):
            c.setFont("Helvetica-Bold", 9)
            c.setFillColor(MUTED)
            c.drawString(20 * mm, y, label.upper())
            c.setFont("Helvetica", 11)
            c.setFillColor(INK)
            c.drawString(20 * mm, y - 6 * mm, value)
            y -= 17 * mm
        c.restoreState()

    def body(c, d):
        w, h = A4
        c.saveState()
        c.setStrokeColor(RULE)
        c.line(20 * mm, h - 14 * mm, w - 20 * mm, h - 14 * mm)
        c.setFont("Helvetica", 7.5)
        c.setFillColor(MUTED)
        c.drawString(20 * mm, h - 11 * mm, f"{eng['entity']}  |  {eng['report_title']}")
        c.drawRightString(w - 20 * mm, h - 11 * mm, "FICTIONAL - LAB EXERCISE")
        c.drawString(20 * mm, 12 * mm, f"Version {eng['version']}  |  {generated}")
        c.drawRightString(w - 20 * mm, 12 * mm, f"Page {d.page}")
        c.restoreState()

    doc.addPageTemplates([PageTemplate(id="cover", frames=[frame], onPage=cover),
                          PageTemplate(id="body", frames=[frame], onPage=body)])
    return doc


# ---------------------------------------------------------------- sections
def apply_acceptances(findings, accepted):
    for f in findings:
        f["accepted"] = None
        for a in accepted:
            if f["finding_id"] in a["finding_ids"] and a["match"] in f["resource"]:
                f["accepted"] = a
    return findings


def executive_summary(findings, meta, eng):
    counts = Counter(f["severity"] for f in findings)
    parts = [f"{counts[s]} {s.lower()}" for s in SEVERITY_ORDER if counts[s]]
    count_text = ", ".join(parts[:-1]) + (" and " if len(parts) > 1 else "") + parts[-1] \
        if parts else "no"
    articles = sorted({f["dora_article"] for f in findings}, key=lambda a: int(a.split()[1]))
    article_text = ", ".join(f"{a} ({DORA_ARTICLES[a]})" for a in articles)

    open_items = [f for f in findings if not f["accepted"]]
    low_effort = [f for f in open_items if f["effort"] == "Low"]
    criticals = [f for f in open_items if f["severity"] == "Critical"]
    crit_low = [f for f in criticals if f["effort"] == "Low"]

    out = [p("1. Executive summary", "h1")]
    out.append(p(
        f"This report presents the results of an automated configuration review of "
        f"{esc(eng['entity'])}'s Amazon Web Services environment in region "
        f"<b>{esc(meta['region'])}</b>, assessed against the ICT risk management requirements of "
        f"the Digital Operational Resilience Act (Regulation (EU) 2022/2554), Chapter II."))
    out.append(p(
        f"The review identified <b>{len(findings)} findings</b>: {count_text}. "
        f"They engage {article_text}."))

    # severity strip
    strip = [[badge(s) for s in SEVERITY_ORDER],
             [Paragraph(f'<font size="18"><b>{counts.get(s, 0)}</b></font>', STY["cell"])
              for s in SEVERITY_ORDER]]
    t = Table(strip, colWidths=[42 * mm] * 4, rowHeights=[6 * mm, 11 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), PANEL),
                           ("LINEAFTER", (0, 0), (-2, -1), 0.6, colors.white),
                           ("LEFTPADDING", (0, 0), (-1, -1), 8),
                           ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    out += [Spacer(1, 4), t, Spacer(1, 8)]

    out.append(p("Most significant risks", "h2"))
    seen = set()
    for f in sorted(open_items, key=lambda x: -x["risk_score"]):
        if f["finding_id"] in seen:
            continue
        seen.add(f["finding_id"])
        out.append(Paragraph(
            f"<b>{esc(f['title'])}</b> ({f['severity']}, score {f['risk_score']}). "
            f"{esc(f['risk_statement'])}", STY["bullet"], bulletText="•"))
        if len(seen) == 3:
            break

    out.append(p("Overall view", "h2"))
    view = (f"{len(low_effort)} of {len(open_items)} open findings can be remediated with low "
            "effort, typically configuration changes that require no architectural work.")
    if criticals:
        view += (f" {len(crit_low)} of the {len(criticals)} critical findings fall into this "
                 "group, so the highest-rated exposure can be closed quickly.")
    accepted_n = len(findings) - len(open_items)
    if accepted_n:
        view += (f" {accepted_n} finding has been formally accepted as a known risk and is "
                 "recorded in section 7 rather than suppressed from this report."
                 if accepted_n == 1 else
                 f" {accepted_n} findings have been formally accepted as known risks and are "
                 "recorded in section 7 rather than suppressed from this report.")
    out.append(p(view))
    out.append(p(
        "Every finding is mapped to the DORA article it engages, the corresponding "
        "ISO/IEC 27001:2022 Annex A control, and the CIS AWS Foundations Benchmark, so that "
        "remediation can be evidenced against each framework from a single piece of work."))
    return out


def scope_and_method(meta, eng):
    out = [p("2. Scope and methodology", "h1")]
    out.append(p("Entity", "h2"))
    out.append(p(esc(eng["entity_description"])))

    out.append(p("Scope", "h2"))
    checks = ", ".join(c.replace("check_", "").replace("_", " ") for c in meta["checks_run"])
    out.append(p(
        f"Configuration of the AWS account in region <b>{esc(meta['region'])}</b>, plus global "
        f"IAM configuration. Automated checks covered: {esc(checks)}. "
        f"Data collection: {esc(meta['generated_at'])} (UTC)."))

    out.append(p("Method", "h2"))
    for step in (
        "Configuration was read through the AWS APIs using read-only calls. No changes were "
        "made to the environment.",
        "Each detected misconfiguration was mapped to a DORA Chapter II article, ISO/IEC "
        "27001:2022 Annex A controls and the CIS AWS Foundations Benchmark.",
        "Inherent risk was scored as likelihood multiplied by impact, each rated 1 to 5. "
        "Where findings compound, as with an administrator lacking MFA, impact is raised.",
        "Residual risk depends on compensating controls a configuration review cannot observe, "
        "and is left for each risk owner to assess.",
        "Account identifiers are redacted throughout this report.",
    ):
        out.append(Paragraph(esc(step), STY["bullet"], bulletText="•"))

    out.append(p("Risk rating", "h2"))
    bands = [[p("Score", "head"), p("Rating", "head"), p("Expected response", "head")]]
    prev = 25
    for minimum, rating in RATING_BANDS:
        bands.append([p(f"{minimum}-{prev}", "cell"), badge(rating),
                      p(TIMEFRAME[rating], "cell")])
        prev = minimum - 1
    out.append(grid_table(bands, [30 * mm, 35 * mm, 105 * mm]))

    out.append(p("Limitations", "h2"))
    for lim in (
        "IAM analysis covers directly attached managed policies. Permissions inherited through "
        "group membership or granted by inline policies are not evaluated.",
        "Coverage is limited to the services listed under Scope. Absence of a finding is not "
        "evidence that an unassessed control is effective.",
        "DORA Articles 5-8, 11 and 13-14 concern governance, process and organisational "
        "measures that cannot be verified from cloud configuration alone.",
        "This is a configuration review, not a penetration test or a formal audit.",
    ):
        out.append(Paragraph(esc(lim), STY["bullet"], bulletText="•"))
    return out


def findings_overview(findings):
    out = [p("3. Findings overview", "h1")]
    rows = [[p(h, "head") for h in ("ID", "Finding", "Resource", "DORA", "Rating")]]
    for f in findings:
        title = esc(f["title"]) + (" <i>(accepted)</i>" if f["accepted"] else "")
        rows.append([p(f["finding_id"], "cell"), p(title, "cell"),
                     p(esc(short(f["resource"])), "cell"), p(f["dora_article"], "cell"),
                     badge(f["severity"], f["risk_score"])])
    out.append(grid_table(rows, [24 * mm, 56 * mm, 46 * mm, 16 * mm, 28 * mm]))
    return out


def short(resource):
    return resource.split(":")[-1] if resource.startswith("arn:") else resource


def dora_coverage(findings):
    out = [p("4. DORA Chapter II coverage", "h1")]
    out.append(p(
        "The table shows which Chapter II obligations the automated checks can evidence, "
        "and where findings were raised. Articles marked as outside automated scope require "
        "document review and interviews."))
    by_article = {}
    for f in findings:
        by_article.setdefault(f["dora_article"], []).append(f)
    tested = {c["dora"] for c in CONTROLS.values()}

    rows = [[p(h, "head") for h in ("Article", "Obligation", "Status", "Findings")]]
    for art, name in CHAPTER_II.items():
        if art in by_article:
            fs = by_article[art]
            worst = min(fs, key=lambda x: SEVERITY_ORDER.index(x["severity"]))["severity"]
            status = badge(worst)
            detail = ", ".join(sorted({x["finding_id"] for x in fs}))
        elif art in tested:
            status, detail = p("No findings", "cell"), "-"
        else:
            status, detail = p('<font color="#6B6B6B">Outside automated scope</font>',
                               "cell"), "-"
        rows.append([p(art, "cellb"), p(name, "cell"), status, p(detail, "cell")])
    out.append(grid_table(rows, [18 * mm, 72 * mm, 38 * mm, 42 * mm]))
    return out


def detailed_findings(findings):
    out = [p("5. Detailed findings", "h1")]
    for f in findings:
        cis = esc(f["cis_title"]) + (f" (CIS {esc(f['cis_id'])})" if f["cis_id"] else "")
        head = Table([[p(f"<b>{f['finding_id']}</b>  {esc(f['title'])}", "cell"),
                       badge(f["severity"], f["risk_score"])]],
                     colWidths=[140 * mm, 30 * mm])
        head.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), PANEL),
                                  ("LINEABOVE", (0, 0), (-1, 0), 2,
                                   SEVERITY_COLOUR[f["severity"]]),
                                  ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                  ("TOPPADDING", (0, 0), (-1, -1), 6),
                                  ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
        rows = [
            ("Resource", esc(f["resource"])),
            ("Observation", esc(f["detail"])),
            ("Risk", esc(f["risk_statement"])),
            ("Scoring", f"Likelihood {f['likelihood']} x Impact {f['impact']} = "
                        f"{f['risk_score']}"),
            ("DORA", f"{f['dora_article']}: {esc(f['dora_title'])}"),
            ("ISO 27001", esc("; ".join(f["iso_27001"]))),
            ("CIS", cis),
            ("Remediation", esc(f["remediation"])),
            ("Effort / owner", f"{f['effort']}  |  {esc(f['owner'])}"),
        ]
        if f["accepted"]:
            rows.append(("Status", "<b>Risk accepted</b>: see section 7"))
        body = Table([[p(k, "label"), p(v, "cell")] for k, v in rows],
                     colWidths=[30 * mm, 140 * mm])
        body.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                  ("LINEBELOW", (0, 0), (-1, -2), 0.3, RULE),
                                  ("TOPPADDING", (0, 0), (-1, -1), 3),
                                  ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
        out.append(KeepTogether([head, body, Spacer(1, 10)]))
    return out


def roadmap(findings):
    out = [p("6. Remediation roadmap", "h1")]
    out.append(p(
        "Open findings are sequenced by inherent risk. Low-effort items within each phase "
        "should be scheduled first, since they close exposure without project overhead."))
    open_items = [f for f in findings if not f["accepted"]]
    effort_rank = {"Low": 0, "Medium": 1, "High": 2}
    for sev in SEVERITY_ORDER:
        group = [f for f in open_items if f["severity"] == sev]
        if not group:
            continue
        out.append(p(f"{TIMEFRAME[sev]}: {sev.lower()} findings", "h2"))
        rows = [[p(h, "head") for h in ("ID", "Action", "Effort", "Owner")]]
        for f in sorted(group, key=lambda x: (effort_rank[x["effort"]], -x["risk_score"])):
            rows.append([p(f["finding_id"], "cell"),
                         p(f"{esc(f['remediation'])}<br/>"
                           f'<font color="#6B6B6B">{esc(short(f["resource"]))}</font>', "cell"),
                         p(f["effort"], "cell"), p(esc(f["owner"]), "cell")])
        out.append(grid_table(rows, [24 * mm, 92 * mm, 18 * mm, 36 * mm]))
    return out


def acceptances(findings):
    accepted = [f for f in findings if f["accepted"]]
    out = [p("7. Risk acceptances", "h1")]
    out.append(p(
        "Accepted risks remain in this report. Suppressing a known finding from a scan "
        "would make the report an incomplete picture of the environment; instead each "
        "acceptance is recorded with its justification, compensating controls and a review date."))
    if not accepted:
        out.append(p("No risks have been formally accepted."))
        return out
    heading, intro = out[0], out[1]
    out = []
    for i, f in enumerate(accepted):
        a = f["accepted"]
        rows = [("Finding", f"{f['finding_id']}: {esc(f['title'])}"),
                ("Resource", esc(f["resource"])),
                ("Justification", esc(a["justification"])),
                ("Compensating controls", esc(a["compensating_controls"])),
                ("Accepted by", esc(a["accepted_by"])),
                ("Review date", esc(a["review_date"]))]
        t = Table([[p(k, "label"), p(v, "cell")] for k, v in rows],
                  colWidths=[38 * mm, 132 * mm])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), PANEL),
                               ("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("LINEBELOW", (0, 0), (-1, -2), 0.3, colors.white)]))
        block = [heading, intro, t] if i == 0 else [t]
        out += [KeepTogether(block), Spacer(1, 8)]
    return out


# ---------------------------------------------------------------- main
def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", default="findings.json")
    ap.add_argument("--engagement", default=os.path.join(here, "..", "engagement.json"))
    ap.add_argument("--accepted", default=os.path.join(here, "..", "accepted_risks.json"))
    ap.add_argument("--out", default=os.path.join(here, "..", "report",
                                                  "assessment-report.pdf"))
    args = ap.parse_args()

    meta = json.load(open(args.findings, encoding="utf-8"))
    eng = json.load(open(args.engagement, encoding="utf-8"))
    accepted = (json.load(open(args.accepted, encoding="utf-8"))
                if os.path.exists(args.accepted) else [])
    findings = apply_acceptances(meta["findings"], accepted)
    generated = datetime.fromisoformat(meta["generated_at"]).strftime("%d %B %Y")

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    doc = make_doc(args.out, eng, generated)

    story = [NextPageTemplate("body"), PageBreak()]
    story += executive_summary(findings, meta, eng)
    story += [PageBreak()] + scope_and_method(meta, eng)
    story += [PageBreak()] + findings_overview(findings)
    story += [Spacer(1, 10)] + dora_coverage(findings)
    story += [PageBreak()] + detailed_findings(findings)
    story += [PageBreak()] + roadmap(findings)
    story += [Spacer(1, 10)] + acceptances(findings)

    doc.build(story)
    print(f"Report written to {args.out}")


if __name__ == "__main__":
    main()
