/** App-level Share Intel workflow: button/nav open sharing with the live result. */

import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "./App";
import { setCsrfToken } from "./api/client";

const HEALTH = {
  status: "ok",
  service: "threatlens-api",
  version: "0.1.0",
  timestamp: "2026-10-31T00:00:00Z",
};

const ANALYSIS = {
  filename: "r.txt",
  file_type: "txt",
  char_count: 42,
  truncated: false,
  model: "muse-spark-1.3",
  warnings: [],
  analysis: {
    executive_summary: "Canned summary for share workflow tests.",
    attack_techniques: [
      {
        name: "Valid Accounts",
        mitre_id: "T1078",
        description: "Stolen creds.",
        evidence_quote: "credential theft",
        inferred: false,
      },
    ],
    indicators_of_compromise: [
      {
        value: "192.0.2.44",
        type: "ip",
        context: "",
        evidence_quote: "saw 192.0.2.44",
        verified_in_source: true,
      },
    ],
    cves: [],
    affected_systems: [],
    recommendations: [],
    supporting_evidence: [],
  },
};

const AUTHED = {
  authenticated: true,
  role: "analyst",
  distribution_enabled: true,
  auth_configured: true,
  csrf_token: "csrf-test-token",
  model_api_configured: true,
  misp_configured: false,
  ai_consent: true,
};

function packageResponse() {
  return {
    package_id: "pkg1234567890",
    analyzed_at: "2026-10-31T00:00:00Z",
    source_filename: "r.txt",
    model: "muse-spark-1.3",
    classification: {
      source_markings: [null],
      effective_source: "TLP:AMBER",
      proposed: "TLP:AMBER",
      downgrade: false,
      analyst_asserted: true,
    },
    audience: "Limited disclosure: the recipient's organization and its clients.",
    audience_note: "",
    analyst_notes: "",
    content: ANALYSIS.analysis,
    content_counts: {
      summary: 1,
      techniques: 1,
      iocs: 1,
      cves: 0,
      systems: 0,
      recommendations: 0,
      evidence: 0,
    },
    warnings: [],
    redactions_applied: 0,
    audit_id: "audit1234567890",
  };
}

const MISP_PREVIEW = {
  event: {
    info: "[ThreatLens] r.txt [TLP:AMBER]",
    distribution: 0,
    sharing_group_id: null,
    threat_level_id: 4,
    analysis: 2,
    published: false,
    tags: ["tlp:amber"],
    attributes: [
      {
        type: "ip-dst",
        value: "192.0.2.44",
        category: "Network activity",
        to_ids: true,
        comment: "verified IOC",
      },
    ],
  },
  warnings: [],
  attribute_count: 1,
  tlp_tag: "tlp:amber",
  destination_check: {
    safe: true,
    reason: "Destination: Your organisation only.",
    verified: false,
  },
};

const STIX_BUNDLE = {
  filename: "threatlens-r-ab12cd34.stix.json",
  media_type: "application/json",
  bundle: { type: "bundle", id: "bundle--1", objects: [] },
  warnings: [],
  object_counts: { identity: 1, report: 1, "marking-definition": 1 },
};

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

let fetchMock: ReturnType<typeof vi.fn>;
let prepareImpl: () => Response = () => jsonResponse(packageResponse());
let mispPreviewImpl: () => Response = () => jsonResponse(MISP_PREVIEW);

function stubFetch() {
  fetchMock = vi.fn(async (url: string | URL | Request) => {
    const target = String(url);
    if (target.includes("/api/health")) return jsonResponse(HEALTH);
    if (target.includes("/api/auth/status")) return jsonResponse(AUTHED);
    if (target.includes("/api/analyze")) return jsonResponse(ANALYSIS);
    if (target.includes("/api/share/prepare")) return prepareImpl();
    if (target.includes("/api/share/pdf"))
      return new Response("%PDF-fake-bytes", {
        status: 200,
        headers: { "Content-Type": "application/pdf" },
      });
    if (target.includes("/api/share/stix")) return jsonResponse(STIX_BUNDLE);
    if (target.includes("/api/misp/preview")) return mispPreviewImpl();
    if (target.includes("/api/export/stix")) return jsonResponse(STIX_BUNDLE);
    if (target.includes("/api/history/records"))
      return jsonResponse({ records: [], total: 0, demo: true, distribution_enabled: true });
    if (target.includes("/api/audit/events"))
      return jsonResponse({ events: [], total: 0 });
    throw new Error(`unexpected fetch: ${target}`);
  });
  vi.stubGlobal("fetch", fetchMock);
}

beforeEach(() => {
  prepareImpl = () => jsonResponse(packageResponse());
  mispPreviewImpl = () => jsonResponse(MISP_PREVIEW);
  stubFetch();
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  setCsrfToken(null);
});

async function renderApp() {
  render(<App />);
  await screen.findByRole("button", { name: "Overview" });
}

function fileInput(): HTMLInputElement {
  const input = document.querySelector('input[type="file"]');
  if (!(input instanceof HTMLInputElement)) throw new Error("file input missing");
  return input;
}

async function analyzeReport(user: ReturnType<typeof userEvent.setup>) {
  await user.upload(
    fileInput(),
    new File(["synthetic report text"], "r.txt", { type: "text/plain" }),
  );
  await user.click(screen.getByRole("button", { name: "Analyze" }));
  await screen.findByText("Analysis: r.txt");
}

async function openShareAndClassify(user: ReturnType<typeof userEvent.setup>) {
  await analyzeReport(user);
  await user.click(screen.getByRole("button", { name: "SHARE INTEL" }));
  await screen.findByRole("heading", { level: 1, name: "Share Intelligence" });
  await user.selectOptions(
    screen.getByLabelText("Analyst classification (required when any source is unmarked)"),
    "TLP:AMBER",
  );
  await user.click(screen.getByRole("radio", { name: "Proposed marking TLP:AMBER" }));
  await user.click(screen.getByRole("checkbox", { name: /I have reviewed/ }));
}

test("share view without analysis shows an explanatory empty state", async () => {
  const user = userEvent.setup();
  await renderApp();
  await user.click(
    within(screen.getByRole("navigation")).getByRole("button", { name: "Share Intel" }),
  );
  expect(
    screen.getByRole("heading", { level: 1, name: "Share Intelligence" }),
  ).toBeTruthy();
  expect(screen.getByText("No completed analysis to share")).toBeTruthy();
  expect(screen.getByText(/built from a completed live analysis/)).toBeTruthy();
  expect(
    fetchMock.mock.calls.some(([url]) => String(url).includes("/api/share/prepare")),
  ).toBe(false);
  await user.click(screen.getByRole("button", { name: "Go to Upload Intel" }));
  expect(
    screen.getByRole("heading", { level: 1, name: "Upload Intelligence" }),
  ).toBeTruthy();
});

test("dashboard Share Intel button opens the share view and preserves analysis", async () => {
  const user = userEvent.setup();
  await renderApp();
  // No analysis yet: the dashboard button opens the share view's empty state.
  await user.click(
    within(screen.getByRole("main")).getByRole("button", { name: "Share Intel" }),
  );
  expect(
    screen.getByRole("heading", { level: 1, name: "Share Intelligence" }),
  ).toBeTruthy();
  expect(screen.getByText("No completed analysis to share")).toBeTruthy();

  // With a completed analysis: the dashboard button carries it into the share view.
  await user.click(screen.getByRole("button", { name: "Go to Upload Intel" }));
  await analyzeReport(user);
  await user.click(
    within(screen.getByRole("navigation")).getByRole("button", { name: "Overview" }),
  );
  await user.click(
    within(screen.getByRole("main")).getByRole("button", { name: "Share Intel" }),
  );
  expect(
    await screen.findByRole("heading", { level: 1, name: "Share Intelligence" }),
  ).toBeTruthy();
  expect(screen.getByText(/Source analysis: r\.txt/)).toBeTruthy();
});

test("SHARE INTEL button carries the completed analysis into the share view", async () => {
  const user = userEvent.setup();
  await renderApp();
  await analyzeReport(user);
  await user.click(screen.getByRole("button", { name: "SHARE INTEL" }));
  expect(
    await screen.findByRole("heading", { level: 1, name: "Share Intelligence" }),
  ).toBeTruthy();
  expect(screen.getByText(/Source analysis: r\.txt/)).toBeTruthy();
  expect(screen.getByText(/MUSE-SPARK-1\.3/)).toBeTruthy();
  expect(screen.getByText(/UNCLASSIFIED — REVIEW REQUIRED/)).toBeTruthy();
  expect(
    fetchMock.mock.calls.some(([url]) => String(url).includes("/api/share/prepare")),
  ).toBe(false);
});

test("TLP review shows source marking and all five output markings", async () => {
  const user = userEvent.setup();
  await renderApp();
  await analyzeReport(user);
  await user.click(screen.getByRole("button", { name: "SHARE INTEL" }));
  await screen.findByRole("heading", { level: 1, name: "Share Intelligence" });
  for (const marking of ["TLP:RED", "TLP:AMBER+STRICT", "TLP:AMBER", "TLP:GREEN", "TLP:CLEAR"]) {
    expect(
      screen.getByRole("radio", { name: `Proposed marking ${marking}` }),
    ).toBeTruthy();
  }
  expect(screen.getByText(/must not share TLP:RED/)).toBeTruthy();
  expect(screen.getByText(/without restriction/)).toBeTruthy();
  await user.selectOptions(
    screen.getByLabelText("Analyst classification (required when any source is unmarked)"),
    "TLP:AMBER",
  );
  expect(screen.getByText(/EFFECTIVE SOURCE: TLP:AMBER/)).toBeTruthy();
});

test("prepare posts the reviewed package with auth and shows the preview", async () => {
  const user = userEvent.setup();
  await renderApp();
  await openShareAndClassify(user);
  await user.click(screen.getByRole("button", { name: /prepare package/i }));
  await screen.findByText("Prepared package — preview");
  expect(screen.getByText("TLP:AMBER → TLP:AMBER")).toBeTruthy();

  const call = fetchMock.mock.calls.find(([url]) => url === "/api/share/prepare");
  expect(call).toBeTruthy();
  const [, opts] = call as [string, RequestInit & { credentials?: string }];
  expect(opts.method).toBe("POST");
  expect(opts.credentials).toBe("include");
  expect((opts.headers as Record<string, string>)["X-CSRF-Token"]).toBe("csrf-test-token");
  const sent = JSON.parse(opts.body as string) as {
    selection: { iocs: string[] };
    approval: { approved: boolean };
    proposed_marking: string;
  };
  expect(sent.selection.iocs).toEqual(["192.0.2.44"]);
  expect(sent.approval.approved).toBe(true);
  expect(sent.proposed_marking).toBe("TLP:AMBER");
});

test("preview exports download TLP-marked PDF and STIX via existing endpoints", async () => {
  const user = userEvent.setup();
  const realCreate = URL.createObjectURL;
  const realRevoke = URL.revokeObjectURL;
  URL.createObjectURL = (() => "blob:fake") as typeof URL.createObjectURL;
  URL.revokeObjectURL = (() => {}) as typeof URL.revokeObjectURL;
  const anchorClick = vi
    .spyOn(HTMLAnchorElement.prototype, "click")
    .mockImplementation(() => {});
  try {
    await renderApp();
    await openShareAndClassify(user);
    await user.click(screen.getByRole("button", { name: /prepare package/i }));
    await screen.findByText("Prepared package — preview");

    await user.click(screen.getByRole("button", { name: /pdf report/i }));
    await vi.waitFor(() => expect(anchorClick).toHaveBeenCalledTimes(1));
    const pdfCall = fetchMock.mock.calls.find(([url]) => url === "/api/share/pdf");
    expect(pdfCall).toBeTruthy();
    const pdfSent = JSON.parse((pdfCall as [string, RequestInit])[1].body as string) as {
      package: { package_id: string };
    };
    expect(pdfSent.package.package_id).toBe("pkg1234567890");
    expect(
      (anchorClick.mock.instances[0] as HTMLAnchorElement).download,
    ).toBe("threatlens-share-pkg12345.pdf");

    await user.click(screen.getByRole("button", { name: /stix bundle/i }));
    await screen.findByText(/STIX bundle: 3 objects/);
    expect(fetchMock.mock.calls.some(([url]) => url === "/api/share/stix")).toBe(true);
    expect(anchorClick).toHaveBeenCalledTimes(2);
    expect(
      (anchorClick.mock.instances[1] as HTMLAnchorElement).download,
    ).toBe("threatlens-r-ab12cd34.stix.json");
  } finally {
    URL.createObjectURL = realCreate;
    URL.revokeObjectURL = realRevoke;
  }
});

test("MISP preview is local-only with metadata, attributes, TLP and restrictions", async () => {
  const user = userEvent.setup();
  await renderApp();
  await openShareAndClassify(user);
  await user.click(screen.getByRole("button", { name: /prepare package/i }));
  await screen.findByText("Prepared package — preview");

  expect(screen.getByText(/MISP EXPORT/)).toBeTruthy();
  await user.click(screen.getByRole("button", { name: /preview event/i }));
  expect(await screen.findByText("[ThreatLens] r.txt [TLP:AMBER]")).toBeTruthy();
  expect(
    within(screen.getByLabelText("MISP export")).getByText("192.0.2.44"),
  ).toBeTruthy();
  expect(screen.getByText(/TAGS:.*tlp:amber/)).toBeTruthy();
  expect(screen.getByText(/ATTRIBUTE\(S\) · UNPUBLISHED/)).toBeTruthy();
  expect(screen.getByText(/Destination: Your organisation only/)).toBeTruthy();
  expect(screen.getByText(/LOCAL-ONLY PREVIEW/)).toBeTruthy();
  expect(screen.getByText(/NOTHING HAS BEEN PUBLISHED/)).toBeTruthy();

  const previews = fetchMock.mock.calls.filter(([url]) => url === "/api/misp/preview");
  expect(previews).toHaveLength(1);
  const sent = JSON.parse((previews[0] as [string, RequestInit])[1].body as string) as {
    destination: { distribution: number };
  };
  expect(sent.destination.distribution).toBe(0);
  expect(
    fetchMock.mock.calls.some(([url]) => /^https?:\/\//.test(String(url))),
  ).toBe(false);
  // Creation stays gated behind explicit approval even with a preview.
  expect(
    (screen.getByRole("button", { name: /create draft/i }) as HTMLButtonElement).disabled,
  ).toBe(true);
});

test("prepare permission-denied surfaces the backend message", async () => {
  prepareImpl = () =>
    jsonResponse(
      {
        detail: {
          code: "forbidden",
          message: "'prepare' needs the analyst role.",
        },
      },
      403,
    );
  const user = userEvent.setup();
  await renderApp();
  await openShareAndClassify(user);
  await user.click(screen.getByRole("button", { name: /prepare package/i }));
  expect(await screen.findByText("Sharing preparation failed.")).toBeTruthy();
  expect(screen.getByText(/needs the analyst role/)).toBeTruthy();
  await user.click(screen.getByRole("button", { name: /back to review/i }));
  expect(screen.getByRole("button", { name: /prepare package/i })).toBeTruthy();
});

test("prepare with an invalid TLP marking surfaces a clear error", async () => {
  prepareImpl = () =>
    jsonResponse(
      {
        detail: { code: "invalid_tlp", message: "Invalid TLP marking in proposed_marking." },
      },
      400,
    );
  const user = userEvent.setup();
  await renderApp();
  await openShareAndClassify(user);
  await user.click(screen.getByRole("button", { name: /prepare package/i }));
  expect(await screen.findByText("Invalid TLP marking.")).toBeTruthy();
});

test("prepare API failure surfaces the backend message without crashing", async () => {
  prepareImpl = () =>
    jsonResponse(
      { detail: { code: "analysis_failed", message: "Unexpected error, retry shortly." } },
      500,
    );
  const user = userEvent.setup();
  await renderApp();
  await openShareAndClassify(user);
  await user.click(screen.getByRole("button", { name: /prepare package/i }));
  expect(await screen.findByText("Sharing preparation failed.")).toBeTruthy();
  expect(screen.getByText(/retry shortly/)).toBeTruthy();
});
