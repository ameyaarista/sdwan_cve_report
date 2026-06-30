"""
families.py — Product family definitions for CVE filtering.

Each family defines:
  vendors          : list of (display_name, [keyword_patterns]) to match against CVE descriptions
  unambiguous      : vendors whose keywords are specific enough to need no secondary check
  vendor_checks    : per-vendor regex for vendors whose names are broad (e.g. "Cisco")
  default_check    : fallback regex for vendors not in vendor_checks or unambiguous
  generic_pattern  : optional catch-all (e.g. r"sd-wan" for the SD-WAN family)

How relevance works
-------------------
1. Scan description against vendor keyword patterns → matched vendor list
2. If vendor in unambiguous  →  accepted immediately
3. If vendor in vendor_checks →  accepted only if vendor_checks[vendor] also matches
4. Otherwise                 →  accepted if default_check matches
5. generic_pattern (if set)  →  accepted regardless of vendor match
"""

import re

# ─────────────────────────────────────────────────────────────────────────────
# Fortinet SD-WAN component regex
# ─────────────────────────────────────────────────────────────────────────────

# Palo Alto Networks secondary check — PAN-OS networking/SD-WAN components
_PALO_SDWAN = re.compile(
    r"\bipsec\b|ike[v\s\d]|\bike\b|\bgre\b|\bmpls\b|"
    r"ssl[\s-]?vpn|\bvpn\b|vpn\s+(tunnel|peer|gateway|concentrator)|\badvpn\b|"
    r"overlay\s+(network|tunnel)|\bbgp\b|\bospf\b|\brip\b|is[\s-]is|eigrp|"
    r"routing\s+protocol|dynamic\s+routing|\bwan\b|"
    r"\bdns\b|\bdhcp\b|\bntp\b|\bsnmp\b|"
    r"traffic\s+(shaping|policing|steering|classif)|\bqos\b|"
    r"\bnat\b|\bsnat\b|\bdnat\b|"
    r"sd[\s-]?wan|zero[\s-]?trust|\bpanos\b|pan[\s-]os",
    re.IGNORECASE,
)

# FortiGate IS the SD-WAN appliance — broad match filtered by this secondary check
_FORTI_SDWAN = re.compile(
    r"\bipsec\b|ike[v\s\d]|\bike\b|\bgre\b|gre\s+tunnel|\bvxlan\b|\bmpls\b|"
    r"ssl[\s-]?vpn|\bvpn\b|vpn\s+(tunnel|peer|gateway|concentrator)|\badvpn\b|"
    r"overlay\s+(network|tunnel)|\bbgp\b|\bospf\b|\brip\b|is[\s-]is|eigrp|"
    r"routing\s+protocol|dynamic\s+routing|route\s+(redistribution|reflector|map|leak)|"
    r"static\s+route|policy[\s-]?based\s+routing|\bwan\b|"
    r"wan\s+(link|interface|optimization|failover|load.balanc)|"
    r"link\s+(monitor|health|failover|aggregation)|\blacp\b|\becmp\b|"
    r"\bdns\b|\bdhcp\b|\bntp\b|\bsnmp\b|"
    r"traffic\s+(shaping|policing|steering|classif)|\bqos\b|bandwidth\s+(control|limit)|"
    r"application\s+(steering|aware|identif)|"
    r"packet\s+(forwarding|processing|filter)|data[\s-]?plane|forwarding[\s-]?plane|"
    r"\bfirewall\b|\bnat\b|\bsnat\b|\bdnat\b|"
    r"sd[\s-]?wan|performance\s+sla|sla\s+(probe|monitor)|\bsase\b|zero[\s-]?trust",
    re.IGNORECASE,
)

# ─────────────────────────────────────────────────────────────────────────────
# SD-WAN vendor keyword list
# ─────────────────────────────────────────────────────────────────────────────

_SDWAN_VENDORS = [
    ("Cisco", [
        r"cisco\s+sd[\s-]?wan", r"\bviptela\b",
        r"cisco\s+catalyst\s+sd[\s-]?wan",
        r"cisco\s+ios[\s-]?xe\s+sd[\s-]?wan",
        r"cisco\s+vedge", r"\bvmanage\b", r"\bvsmart\b", r"\bvbond\b",
    ]),
    ("Arista", [
        r"vmware\s+sd[\s-]?wan", r"\bvelocloud\b", r"broadcom\s+sd[\s-]?wan",
        r"arista\s+sd[\s-]?wan",
    ]),
    # FortiGate IS the SD-WAN appliance — broad match, filtered by _FORTI_SDWAN
    ("Fortinet", [
        r"\bfortigate\b", r"\bfortios\b", r"\bfortimanager\b",
        r"\bfortisase\b", r"\bfortinet\b",
    ]),
    ("Palo Alto Networks", [
        r"prisma\s+sd[\s-]?wan", r"\bcloudgenix\b", r"palo\s+alto.*sd[\s-]?wan",
        r"\bpan[\s-]?os\b", r"palo\s+alto\s+networks",
    ]),
    ("Juniper", [
        r"juniper.*sd[\s-]?wan", r"session\s+smart\s+router",
        r"128\s+technology", r"128t\s+router", r"juniper.*wan\s+assurance",
    ]),
    ("HPE Aruba", [
        r"silver\s+peak", r"hpe.*edgeconnect",
        r"aruba.*edgeconnect", r"aruba.*sd[\s-]?wan", r"edgeconnect\s+sd[\s-]?wan",
    ]),
    ("Versa Networks", [
        r"versa\s+networks", r"versa\s+flexvnf",
        r"versa\s+sd[\s-]?wan", r"\bversaos\b",
    ]),
    ("Generic",     [r"\bsd[\s-]?wan\b"]),
]

# ─────────────────────────────────────────────────────────────────────────────
# Family config
# ─────────────────────────────────────────────────────────────────────────────

FAMILIES: dict[str, dict] = {

    "SDWAN": {
        "display_name":  "SD-WAN",
        "vendors":       _SDWAN_VENDORS,
        # These vendors exclusively make SD-WAN products — no secondary check needed
        "unambiguous":   {"Arista", "Versa Networks", "HPE Aruba"},
        # Per-vendor secondary check for broad-name vendors
        "vendor_checks": {
            "Fortinet":           _FORTI_SDWAN,
            "Palo Alto Networks": _PALO_SDWAN,
        },
        # Reject CVEs matching these patterns even if vendor_checks passes
        "vendor_excludes": {
            "Palo Alto Networks": re.compile(
                r"\bglobal[\s-]?protect\b|\bcortex\b|\bcortex[\s-]?xdr\b",
                re.IGNORECASE
            ),
        },
        # Fallback for Cisco, Juniper — need explicit SD-WAN term
        "default_check": re.compile(
            r"sd[\s-]?wan|viptela|vedge|vmanage|vsmart|vbond|"
            r"velocloud|session\s+smart|128t|cloudgenix|edgeconnect|"
            r"versaos|flexvnf|\badvpn\b",
            re.IGNORECASE,
        ),
        # A description containing only this (with no specific vendor) still counts
        "generic_pattern": re.compile(r"\bsd[\s-]?wan\b", re.IGNORECASE),
    },
}
