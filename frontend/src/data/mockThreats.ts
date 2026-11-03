export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Threat {
  id: string;
  title: string;
  severity: Severity;
  sector: string;
  source: string;
  detectedAt: string;
  summary: string;
  iocs: number;
  status: "new" | "triaging" | "contained" | "monitoring";
}

export interface DashboardStats {
  activeThreats: number;
  criticalCount: number;
  reportsAnalyzed: number;
  iocsTracked: number;
  deltaActive: number;
  deltaReports: number;
}

export const mockStats: DashboardStats = {
  activeThreats: 47,
  criticalCount: 6,
  reportsAnalyzed: 312,
  iocsTracked: 1843,
  deltaActive: 12,
  deltaReports: 28,
};

export const severityCounts: Record<Severity, number> = {
  critical: 6,
  high: 14,
  medium: 17,
  low: 8,
  info: 2,
};

export const sectorExposure: { sector: string; threats: number }[] = [
  { sector: "Power Generation", threats: 18 },
  { sector: "Transmission Grid", threats: 12 },
  { sector: "Oil & Gas", threats: 9 },
  { sector: "Water / Utilities", threats: 5 },
  { sector: "Renewables", threats: 3 },
];

export const mockThreats: Threat[] = [
  {
    id: "TL-2026-1042",
    title: "Ransomware crew targeting SCADA historians via exposed RDP",
    severity: "critical",
    sector: "Power Generation",
    source: "CISA AA26-301A",
    detectedAt: "2026-10-30T22:14:00Z",
    summary:
      "Threat actor observed encrypting OSIsoft PI historians after initial access through an internet-facing engineering workstation.",
    iocs: 24,
    status: "triaging",
  },
  {
    id: "TL-2026-1041",
    title: "Phishing wave impersonating grid operator outage notices",
    severity: "high",
    sector: "Transmission Grid",
    source: "TL Sensor Net",
    detectedAt: "2026-10-30T18:02:00Z",
    summary:
      "Credential-harvesting lures themed as planned-outage alerts sent to utility staff; 3 confirmed clicks, no session theft yet.",
    iocs: 11,
    status: "monitoring",
  },
  {
    id: "TL-2026-1039",
    title: "Suspected ICS reconnaissance against Modbus/TCP gateways",
    severity: "high",
    sector: "Oil & Gas",
    source: "Partner Feed",
    detectedAt: "2026-10-29T09:47:00Z",
    summary:
      "Low-and-slow function-code scans from rotating infrastructure against pipeline telemetry gateways across two regions.",
    iocs: 37,
    status: "monitoring",
  },
  {
    id: "TL-2026-1036",
    title: "Vulnerability disclosure: VPN appliance RCE under active exploit",
    severity: "critical",
    sector: "Transmission Grid",
    source: "Vendor Advisory",
    detectedAt: "2026-10-28T15:20:00Z",
    summary:
      "Unauthenticated RCE in edge VPN devices widely deployed at substations; exploit code public, patch window closing.",
    iocs: 8,
    status: "triaging",
  },
  {
    id: "TL-2026-1031",
    title: "Typosquatted packages in OT software supply chain",
    severity: "medium",
    sector: "Power Generation",
    source: "TL Sensor Net",
    detectedAt: "2026-10-27T11:05:00Z",
    summary:
      "Lookalike PyPI packages mimicking a turbine-diagnostics SDK exfiltrate environment variables on install.",
    iocs: 5,
    status: "contained",
  },
  {
    id: "TL-2026-1028",
    title: "DDoS-for-hire chatter referencing regional utility portals",
    severity: "low",
    sector: "Water / Utilities",
    source: "Dark Web Monitor",
    detectedAt: "2026-10-26T07:33:00Z",
    summary:
      "Forum posts soliciting stresser attacks on customer portals; no capability demonstrated, watch-level only.",
    iocs: 2,
    status: "monitoring",
  },
  {
    id: "TL-2026-1024",
    title: "Firmware implants found in decommissioned RTU shipment",
    severity: "high",
    sector: "Transmission Grid",
    source: "Field Report",
    detectedAt: "2026-10-24T16:58:00Z",
    summary:
      "Forensic teardown of returned remote terminal units revealed persistent boot-stage implants; procurement review opened.",
    iocs: 19,
    status: "triaging",
  },
  {
    id: "TL-2026-1019",
    title: "Quarterly threat landscape brief: energy sector Q4",
    severity: "info",
    sector: "Renewables",
    source: "TL Research",
    detectedAt: "2026-10-22T13:00:00Z",
    summary:
      "Standing brief covering actor trends, exploited CVEs, and defensive recommendations for Q4 planning.",
    iocs: 0,
    status: "contained",
  },
];
