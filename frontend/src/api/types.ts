/** Mirrors backend/app/schemas.py — structured analysis results. */

export interface EvidenceItem {
  quote: string;
  relevance: string;
}

export interface AttackTechnique {
  name: string;
  mitre_id: string | null;
  description: string;
  evidence_quote: string;
  inferred: boolean;
}

export type IocType =
  | "ip"
  | "domain"
  | "url"
  | "hash"
  | "email"
  | "filename"
  | "mutex"
  | "other";

export interface IOC {
  value: string;
  type: IocType;
  context: string;
  evidence_quote: string;
  verified_in_source: boolean;
}

export interface CVERef {
  id: string;
  description: string;
  evidence_quote: string;
  verified_in_source: boolean;
}

export interface AffectedSystem {
  system: string;
  detail: string;
  evidence_quote: string;
  inferred: boolean;
}

export interface Recommendation {
  recommendation: string;
  priority: "critical" | "high" | "medium" | "low";
  rationale: string;
}

export interface AnalysisResult {
  executive_summary: string;
  attack_techniques: AttackTechnique[];
  indicators_of_compromise: IOC[];
  cves: CVERef[];
  affected_systems: AffectedSystem[];
  recommendations: Recommendation[];
  supporting_evidence: EvidenceItem[];
}

export interface AnalyzeResponse {
  filename: string;
  file_type: "pdf" | "txt";
  char_count: number;
  truncated: boolean;
  model: string;
  analyzed_at: string;
  warnings: string[];
  analysis: AnalysisResult;
}

export interface StixExportResponse {
  filename: string;
  media_type: "application/json";
  bundle: Record<string, unknown>;
  warnings: string[];
  object_counts: Record<string, number>;
}

export interface ShareSource {
  name: string;
  marking: string | null;
}

export interface ShareSelection {
  include_summary: boolean;
  techniques: number[];
  iocs: string[];
  cves: string[];
  systems: string[];
  recommendations: number[];
  evidence: number[];
}

export interface ShareRedaction {
  match: string;
  replacement: string;
}

export interface ShareApproval {
  approved: boolean;
  analyst: string;
  justification: string;
  downgrade_accepted: boolean;
}

export interface SharePrepareRequest {
  analysis: AnalyzeResponse;
  sources: ShareSource[];
  analyst_source_marking: string | null;
  proposed_marking: string;
  selection: ShareSelection;
  redactions: ShareRedaction[];
  approval: ShareApproval | null;
  audience_note: string;
  analyst_notes: string;
}

export interface ShareClassification {
  source_markings: (string | null)[];
  effective_source: string;
  proposed: string;
  downgrade: boolean;
  analyst_asserted: boolean;
}

export interface SharePrepareResponse {
  package_id: string;
  prepared_at: string;
  analyzed_at: string | null;
  source_filename: string;
  model: string;
  classification: ShareClassification;
  audience: string;
  audience_note: string;
  analyst_notes: string;
  content: AnalysisResult;
  content_counts: Record<string, number>;
  warnings: string[];
  redactions_applied: number;
  audit_id: string;
}

/** Mirrors backend MISP schemas — destination, preview, create, publish. */

export interface MispDestinationChoice {
  distribution: number;
  sharing_group_id: number | null;
}

export interface MispApproval {
  approved: boolean;
  confirmed: boolean;
}

export interface MispAttribute {
  type: string;
  value: string;
  category: string;
  to_ids: boolean;
  comment: string;
}

export interface MispEventPreview {
  info: string;
  distribution: number;
  sharing_group_id: number | null;
  threat_level_id: number;
  analysis: number;
  published: boolean;
  tags: string[];
  attributes: MispAttribute[];
}

export interface MispDestinationCheck {
  safe: boolean;
  reason: string;
  verified: boolean;
}

export interface MispPreviewResponse {
  event: MispEventPreview;
  warnings: string[];
  attribute_count: number;
  tlp_tag: string;
  destination_check: MispDestinationCheck | null;
}

export interface MispCreateResponse {
  event_id: string | number;
  event_uuid: string;
  url: string;
  duplicate: boolean;
  warnings: string[];
}

export interface MispPublishResponse {
  event_uuid: string;
  published: boolean;
}

export interface MispTestResponse {
  ok: boolean;
  url: string;
  org: string;
  role: string;
  can_add: boolean;
  can_publish: boolean;
  error: { code: string; message: string } | null;
}

/** Mirrors backend Phase 4 history/audit/auth schemas. */

export interface HistoryRecord {
  id: string;
  report_id: string;
  package_id: string;
  classification: string;
  destination_kind: string;
  destination_label: string;
  destination_detail: Record<string, unknown>;
  findings: Record<string, number>;
  analyst: string;
  approved_at: string | null;
  status: string;
  misp_event_uuid: string | null;
  error: string | null;
  demo: boolean;
  created_at: string;
  updated_at: string;
}

export interface HistoryListResponse {
  records: HistoryRecord[];
  total: number;
  demo: boolean;
  distribution_enabled: boolean;
}

export interface AuditListResponse {
  events: Record<string, unknown>[];
  total: number;
}

export interface AuthStatusResponse {
  authenticated: boolean;
  role: string;
  distribution_enabled: boolean;
  auth_configured: boolean;
  csrf_token: string | null;
  model_api_configured: boolean;
  misp_configured: boolean;
  ai_consent: boolean;
}

export interface ConsentResponse {
  acknowledged: boolean;
}

export interface LoginResponse {
  role: string;
  csrf_token: string;
  expires_in_seconds: number;
}

export interface HistoryFilters {
  status?: string;
  classification?: string;
  report?: string;
  recipient?: string;
  since?: string;
  until?: string;
}
