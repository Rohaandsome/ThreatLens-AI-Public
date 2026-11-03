/** TLP 2.0 display data for the share UI (mirrors backend/app/services/tlp.py).

The backend is authoritative and re-validates everything; this module only
drives preview text and client-side gating.
*/

export interface TlpLevel {
  marking: string;
  short: string;
  level: number;
  audience: string;
}

export const TLP_LEVELS: TlpLevel[] = [
  {
    marking: "TLP:RED",
    short: "RED",
    level: 4,
    audience:
      "Restricted to named recipients present. Recipients must not share TLP:RED information with any other parties.",
  },
  {
    marking: "TLP:AMBER+STRICT",
    short: "AMBER+STRICT",
    level: 3,
    audience:
      "Restricted to the recipient's organization only, on a need-to-know basis. No sharing with clients or outside parties.",
  },
  {
    marking: "TLP:AMBER",
    short: "AMBER",
    level: 2,
    audience:
      "Limited disclosure: the recipient's organization and its clients, on a need-to-know basis.",
  },
  {
    marking: "TLP:GREEN",
    short: "GREEN",
    level: 1,
    audience:
      "Limited disclosure: the trusted community (for example peer CSIRTs and ISACs). Do not publish publicly.",
  },
  {
    marking: "TLP:CLEAR",
    short: "CLEAR",
    level: 0,
    audience: "May be distributed without restriction (subject to copyright).",
  },
];

const BY_MARKING = new Map(TLP_LEVELS.map((l) => [l.marking, l]));

export function tlpLevel(marking: string): number {
  return BY_MARKING.get(marking)?.level ?? -1;
}

export function tlpAudience(marking: string): string {
  return BY_MARKING.get(marking)?.audience ?? "Unknown marking.";
}

/** Most restrictive of the given markings (display preview only). */
export function mostRestrictive(markings: string[]): string | null {
  let best: TlpLevel | null = null;
  for (const m of markings) {
    const level = BY_MARKING.get(m);
    if (level && (!best || level.level > best.level)) best = level;
  }
  return best?.marking ?? null;
}
