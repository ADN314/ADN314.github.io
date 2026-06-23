// Portfolio content. Placeholder persona — swap for real content later.
window.PORTFOLIO = {
  identity: {
    name: "Morgan Vale",
    handle: "m0rgan",
    role: "Offensive Security Engineer",
    tagline: "I break systems so attackers can't.",
    location: "Berlin, DE",
    availability: "Open to select engagements",
    blurb:
      "Penetration tester and red-team operator with 8+ years finding the holes that scanners miss. I turn adversarial thinking into concrete, fixable findings — and write reports your engineers will actually read.",
  },
  stats: [
    { value: "120+", label: "Engagements led" },
    { value: "9", label: "CVEs published" },
    { value: "40+", label: "Orgs hardened" },
    { value: "0", label: "Findings left unexplained" },
  ],
  skills: [
    {
      group: "Offensive",
      items: ["Web & API pentest", "Network / AD", "Red teaming", "Social engineering", "Physical entry", "Exploit dev"],
    },
    {
      group: "Defensive",
      items: ["Threat modeling", "Detection engineering", "Incident response", "Purple teaming", "Hardening"],
    },
    {
      group: "Cloud & Infra",
      items: ["AWS", "GCP", "Kubernetes", "Terraform IaC review", "Container escape"],
    },
    {
      group: "Tooling",
      items: ["Burp Suite", "Cobalt Strike", "Nmap", "Ghidra", "Metasploit", "Custom Python / Go"],
    },
  ],
  projects: [
    {
      id: "fintech-redteam",
      name: "Full-scope red team — neobank",
      kind: "Red Team",
      year: "2025",
      summary:
        "Adversary simulation against a 4M-user neobank. Started from zero access, reached core payment infra in 9 days.",
      role: "Lead operator",
      duration: "3 weeks",
      impact: [
        "Chained an SSRF + IAM misconfig to pivot into production VPC",
        "Demonstrated unauthorized access to tokenized card data store",
        "Drove 14 high/critical fixes; mean time-to-remediate cut to 6 days",
      ],
      stack: ["AWS", "Kubernetes", "Cobalt Strike", "Custom C2"],
    },
    {
      id: "cve-iot",
      name: "Firmware teardown — industrial gateway",
      kind: "Research",
      year: "2024",
      summary:
        "Reverse-engineered a widely deployed OT gateway, uncovering a pre-auth RCE chain affecting 200k+ devices.",
      role: "Solo researcher",
      duration: "6 weeks",
      impact: [
        "Identified 3 memory-corruption bugs in the web management daemon",
        "Built a reliable pre-auth RCE exploit; coordinated 90-day disclosure",
        "Assigned CVE-2024-XXXXX, CVE-2024-XXXXY, CVE-2024-XXXXZ",
      ],
      stack: ["Ghidra", "QEMU", "Python", "Binary diffing"],
    },
    {
      id: "saas-appsec",
      name: "AppSec program build-out — SaaS scale-up",
      kind: "Advisory",
      year: "2024",
      summary:
        "Stood up an application security program from scratch for a 200-engineer company shipping daily.",
      role: "Embedded consultant",
      duration: "4 months",
      impact: [
        "Introduced threat modeling into the design review gate",
        "Wired SAST/DAST into CI with a triage SLA that engineers trusted",
        "Reduced recurring vuln classes by 70% over two quarters",
      ],
      stack: ["Semgrep", "GitHub Actions", "Threat Dragon", "Terraform"],
    },
    {
      id: "purple-detect",
      name: "Detection engineering sprint",
      kind: "Purple Team",
      year: "2023",
      summary:
        "Two-week purple-team engagement mapping real attacker TTPs to gaps in the SOC's detection coverage.",
      role: "Purple lead",
      duration: "2 weeks",
      impact: [
        "Emulated 30 ATT&CK techniques against the live estate",
        "Authored 22 high-fidelity detections; closed 18 coverage gaps",
        "Cut median alert triage time by tuning out 4 noisy rules",
      ],
      stack: ["Atomic Red Team", "Splunk", "Sigma", "MITRE ATT&CK"],
    },
  ],
  certs: [
    { abbr: "OSCP", name: "Offensive Security Certified Professional" },
    { abbr: "OSEP", name: "Offensive Security Experienced Penetration Tester" },
    { abbr: "OSWE", name: "Offensive Security Web Expert" },
    { abbr: "CRTO", name: "Certified Red Team Operator" },
    { abbr: "GXPN", name: "GIAC Exploit Researcher & Advanced Pen Tester" },
  ],
  experience: [
    {
      period: "2022 — now",
      role: "Principal Security Engineer",
      org: "Vantage Offensive",
      note: "Lead red-team & research practice. Set methodology, mentor 6 operators.",
    },
    {
      period: "2019 — 2022",
      role: "Senior Penetration Tester",
      org: "NorthGate Security",
      note: "Web, network, and cloud engagements for finance & healthcare clients.",
    },
    {
      period: "2017 — 2019",
      role: "Security Analyst",
      org: "Helix SOC",
      note: "Detection, IR, and the engagements nobody else wanted. Learned fast.",
    },
  ],
  contact: {
    email: "morgan@vale.sec",
    pgp: "0xA1B2 C3D4 E5F6 7890",
    links: [
      { label: "GitHub", handle: "@m0rgan" },
      { label: "Mastodon", handle: "@morgan@infosec.exchange" },
      { label: "Signal", handle: "on request" },
    ],
  },
};
