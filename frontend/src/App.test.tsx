/** Frontend interaction tests: every dashboard control must actually work. */

import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
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
    executive_summary: "Canned summary for interaction tests.",
    attack_techniques: [],
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

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

let fetchMock: ReturnType<typeof vi.fn>;

const STIX_EXPORT = {
  filename: "threatlens-r-ab12cd34.stix.json",
  media_type: "application/json",
  bundle: { type: "bundle", id: "bundle--1234", objects: [] },
  warnings: ["IOC 'x' skipped (malformed): value is not a well-formed indicator."],
  object_counts: { identity: 1, indicator: 1, report: 1 },
};

const AUTHED = {
  authenticated: true,
  role: "analyst",
  distribution_enabled: true,
  auth_configured: true,
  csrf_token: "csrf-test-token",
  model_api_configured: false,
  misp_configured: false,
  ai_consent: true,
};

const ANON = {
  authenticated: false,
  role: "anonymous",
  distribution_enabled: false,
  auth_configured: true,
  csrf_token: null,
  model_api_configured: false,
  misp_configured: false,
  ai_consent: false,
};

let statusPayload: unknown = AUTHED;
let loginImpl: () => Response = () =>
  jsonResponse({ role: "analyst", csrf_token: "csrf-test-token", expires_in_seconds: 43200 });

function stubFetch(
  analyzeImpl?: () => Response,
  exportImpl?: () => Response,
  consentImpl?: () => Response,
) {
  fetchMock = vi.fn(async (url: string | URL | Request) => {
    const target = String(url);
    if (target.includes("/api/health")) return jsonResponse(HEALTH);
    if (target.includes("/api/auth/consent"))
      return consentImpl ? consentImpl() : jsonResponse({ acknowledged: true });
    if (target.includes("/api/auth/login")) return loginImpl();
    if (target.includes("/api/auth/logout")) {
      statusPayload = ANON;
      return jsonResponse({ logged_out: true });
    }
    if (target.includes("/api/export/stix"))
      return exportImpl ? exportImpl() : jsonResponse(STIX_EXPORT);
    if (target.includes("/api/analyze"))
      return analyzeImpl ? analyzeImpl() : jsonResponse(ANALYSIS);
    if (target.includes("/api/auth/status")) return jsonResponse(statusPayload);
    if (target.includes("/api/history/records"))
      return jsonResponse({ records: [], total: 0, demo: true, distribution_enabled: false });
    if (target.includes("/api/audit/events"))
      return jsonResponse({ events: [], total: 0 });
    throw new Error(`unexpected fetch: ${target}`);
  });
  vi.stubGlobal("fetch", fetchMock);
}

beforeEach(() => {
  statusPayload = AUTHED;
  loginImpl = () =>
    jsonResponse({ role: "analyst", csrf_token: "csrf-test-token", expires_in_seconds: 43200 });
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

test("sidebar navigation switches views and marks the active item", async () => {
  const user = userEvent.setup();
  await renderApp();
  expect(
    screen.getByRole("heading", { level: 1, name: "Security Operations Overview" }),
  ).toBeTruthy();

  const cases: [string, string][] = [
    ["Threat Feed", "Threat Feed"],
    ["Reports", "Analysis Reports"],
    ["Upload Intel", "Upload Intelligence"],
    ["History", "Sharing History"],
    ["Settings", "Settings"],
    ["Overview", "Security Operations Overview"],
  ];
  for (const [nav, heading] of cases) {
    await user.click(screen.getByRole("button", { name: nav }));
    expect(screen.getByRole("heading", { level: 1, name: heading })).toBeTruthy();
    expect(
      screen.getByRole("button", { name: nav }).getAttribute("aria-current"),
    ).toBe("page");
  }
});

test("settings view shows live backend health", async () => {
  const user = userEvent.setup();
  await renderApp();
  await user.click(screen.getByRole("button", { name: "Settings" }));
  expect(await screen.findByText("threatlens-api")).toBeTruthy();
  expect(screen.getByText("v0.1.0")).toBeTruthy();
  // AUTHED session reports model and MISP as unconfigured.
  expect(screen.getByText(/add MODEL_API_KEY/)).toBeTruthy();
  expect(screen.getByText(/set MISP_URL and MISP_API_KEY/)).toBeTruthy();
});

test("upload dropzone click opens the native file picker", async () => {
  const user = userEvent.setup();
  const clickSpy = vi
    .spyOn(HTMLInputElement.prototype, "click")
    .mockImplementation(() => {});
  await renderApp();
  await user.click(screen.getByRole("button", { name: /browse files/i }));
  expect(clickSpy).toHaveBeenCalledTimes(1);
});

test("analyze sends the file to POST /api/analyze and shows results", async () => {
  const user = userEvent.setup();
  await renderApp();
  await user.upload(
    fileInput(),
    new File(["synthetic report text"], "r.txt", { type: "text/plain" }),
  );
  await user.click(screen.getByRole("button", { name: "Analyze" }));

  await screen.findByText("Analysis: r.txt");
  expect(screen.getByText("Canned summary for interaction tests.")).toBeTruthy();
  expect(screen.getByText("192.0.2.44")).toBeTruthy();

  const call = fetchMock.mock.calls.find(([url]) => url === "/api/analyze");
  expect(call).toBeTruthy();
  const [, opts] = call as [string, RequestInit];
  expect(opts.method).toBe("POST");
  const body = opts.body as FormData;
  expect(body).toBeInstanceOf(FormData);
  const sent = body.get("file") as File;
  expect(sent).toBeInstanceOf(File);
  expect(sent.name).toBe("r.txt");
});

test("remove button drops a queued file", async () => {
  const user = userEvent.setup();
  await renderApp();
  await user.upload(
    fileInput(),
    new File(["x"], "drop-me.txt", { type: "text/plain" }),
  );
  expect(screen.getByText("drop-me.txt")).toBeTruthy();
  await user.click(screen.getByRole("button", { name: "Remove drop-me.txt" }));
  expect(screen.queryByText("drop-me.txt")).toBeNull();
});

test("server errors render a friendly state with working retry", async () => {
  stubFetch(() =>
    jsonResponse(
      {
        detail: {
          code: "model_api_not_configured",
          message: "MODEL_API_KEY is not configured.",
        },
      },
      503,
    ),
  );
  const user = userEvent.setup();
  await renderApp();
  await user.upload(
    fileInput(),
    new File(["x"], "r.txt", { type: "text/plain" }),
  );
  await user.click(screen.getByRole("button", { name: "Analyze" }));

  expect(await screen.findByText("AI analysis isn't configured yet.")).toBeTruthy();
  await user.click(screen.getByRole("button", { name: /retry analysis/i }));
  const analyzeCalls = fetchMock.mock.calls.filter(([url]) => url === "/api/analyze");
  expect(analyzeCalls.length).toBe(2);
});

test("truncated model output renders a specific message", async () => {
  stubFetch(() =>
    jsonResponse(
      {
        detail: {
          code: "model_output_truncated",
          message: "Model response was cut off before completing.",
        },
      },
      502,
    ),
  );
  const user = userEvent.setup();
  await renderApp();
  await user.upload(
    fileInput(),
    new File(["x"], "r.txt", { type: "text/plain" }),
  );
  await user.click(screen.getByRole("button", { name: "Analyze" }));
  expect(await screen.findByText("The AI response was cut off.")).toBeTruthy();
  expect(screen.getByText(/MODEL_MAX_TOKENS/)).toBeTruthy();
});

test("search filters the threat feed", async () => {
  const user = userEvent.setup();
  await renderApp();
  expect(screen.getByText("TL-2026-1042")).toBeTruthy();
  expect(screen.getByText("TL-2026-1041")).toBeTruthy();

  await user.type(
    screen.getByRole("searchbox", { name: "Search threat feed" }),
    "ransomware",
  );
  expect(screen.getByText("TL-2026-1042")).toBeTruthy();
  expect(screen.queryByText("TL-2026-1041")).toBeNull();
  expect(screen.getByText(/FILTERED/)).toBeTruthy();
});

test("stix export posts the analysis and downloads the bundle", async () => {
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
    await user.upload(
      fileInput(),
      new File(["x"], "r.txt", { type: "text/plain" }),
    );
    await user.click(screen.getByRole("button", { name: "Analyze" }));
    await screen.findByText("Analysis: r.txt");

    await user.click(screen.getByRole("button", { name: /stix 2\.1 json/i }));
    await screen.findByText(/Exported 3 STIX objects/);

    const call = fetchMock.mock.calls.find(([url]) => url === "/api/export/stix");
    expect(call).toBeTruthy();
    const [, opts] = call as [string, RequestInit];
    expect(opts.method).toBe("POST");
    const sent = JSON.parse(opts.body as string) as { analysis: { executive_summary: string } };
    expect(sent.analysis.executive_summary).toBe(
      "Canned summary for interaction tests.",
    );

    expect(anchorClick).toHaveBeenCalledTimes(1);
    const anchor = anchorClick.mock.instances[0] as HTMLAnchorElement;
    expect(anchor.download).toBe("threatlens-r-ab12cd34.stix.json");
    expect(anchor.href).toBe("blob:fake");
    expect(screen.getByText(/IOC 'x' skipped/)).toBeTruthy();
  } finally {
    URL.createObjectURL = realCreate;
    URL.revokeObjectURL = realRevoke;
  }
});

test("reports view links to upload when there are no analyses", async () => {
  const user = userEvent.setup();
  await renderApp();
  await user.click(screen.getByRole("button", { name: "Reports" }));
  await user.click(screen.getByRole("button", { name: "Go to Upload Intel" }));
  expect(
    screen.getByRole("heading", { level: 1, name: "Upload Intelligence" }),
  ).toBeTruthy();
});

test("login gate blocks anonymous visitors", async () => {
  statusPayload = ANON;
  render(<App />);
  expect(await screen.findByText("OPERATOR LOGIN")).toBeTruthy();
  expect(screen.getByLabelText("Operator key")).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Overview" })).toBeNull();
  expect(
    fetchMock.mock.calls.map((args: unknown[]) => String(args[0])).join(" "),
  ).not.toContain("/api/analyze");
});

test("login flow unlocks the dashboard", async () => {
  statusPayload = ANON;
  loginImpl = () => {
    statusPayload = AUTHED;
    return jsonResponse({ role: "analyst", csrf_token: "csrf-test-token", expires_in_seconds: 43200 });
  };
  const user = userEvent.setup();
  render(<App />);
  await user.type(await screen.findByLabelText("Operator key"), "operator-key-from-env");
  await user.click(screen.getByRole("button", { name: /^Log in$/ }));
  expect(await screen.findByRole("button", { name: "Overview" })).toBeTruthy();
  const bodies = fetchMock.mock.calls
    .map((args: unknown[]) => String(args[0]))
    .filter((u) => u.includes("/api/auth/login"));
  expect(bodies).toHaveLength(1);
});

test("wrong operator key shows an error and stays gated", async () => {
  statusPayload = ANON;
  loginImpl = () =>
    jsonResponse({ detail: { code: "invalid_credentials", message: "Invalid operator key." } }, 401);
  const user = userEvent.setup();
  render(<App />);
  await user.type(await screen.findByLabelText("Operator key"), "wrong");
  await user.click(screen.getByRole("button", { name: /^Log in$/ }));
  expect(await screen.findByText("Invalid operator key.")).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Overview" })).toBeNull();
});

test("unconfigured backend shows setup guidance", async () => {
  statusPayload = { ...ANON, auth_configured: false };
  render(<App />);
  expect(await screen.findByText(/Generate/)).toBeTruthy();
  expect(screen.getByText(/OPERATOR_API_KEY/)).toBeTruthy();
});

test("log out returns to the login screen", async () => {
  const user = userEvent.setup();
  await renderApp();
  await user.click(screen.getByRole("button", { name: "LOG OUT" }));
  expect(await screen.findByText("OPERATOR LOGIN")).toBeTruthy();
});

test("analysis is blocked until external-AI processing is acknowledged", async () => {
  statusPayload = { ...AUTHED, ai_consent: false };
  const user = userEvent.setup();
  await renderApp();
  expect(screen.getByRole("note", { name: "External AI processing notice" })).toBeTruthy();
  expect(screen.getByText(/sent to the Meta Model API/)).toBeTruthy();
  expect(screen.getByText(/NDA-protected/)).toBeTruthy();
  const ack = screen.getByRole("button", { name: "Acknowledge for this session" });
  expect((ack as HTMLButtonElement).disabled).toBe(true);
  await user.upload(
    fileInput(),
    new File(["x"], "r.txt", { type: "text/plain" }),
  );
  const analyze = screen.getByRole("button", { name: "Analyze" });
  expect((analyze as HTMLButtonElement).disabled).toBe(true);
  expect(fetchMock.mock.calls.some(([url]) => url === "/api/analyze")).toBe(false);
});

test("acknowledging posts consent once and enables analysis", async () => {
  statusPayload = { ...AUTHED, ai_consent: false };
  const user = userEvent.setup();
  await renderApp();
  await user.click(screen.getByRole("checkbox"));
  const ack = screen.getByRole("button", { name: "Acknowledge for this session" });
  expect((ack as HTMLButtonElement).disabled).toBe(false);
  await user.click(ack);
  expect(await screen.findByText(/ACKNOWLEDGED FOR THIS SESSION/)).toBeTruthy();
  const consentCalls = fetchMock.mock.calls.filter(([url]) => url === "/api/auth/consent");
  expect(consentCalls).toHaveLength(1);
  const [, opts] = consentCalls[0] as [string, RequestInit];
  expect(opts.method).toBe("POST");
  expect(opts.body).toBe(JSON.stringify({ acknowledged: true }));
  await user.upload(
    fileInput(),
    new File(["x"], "r.txt", { type: "text/plain" }),
  );
  const analyze = screen.getByRole("button", { name: "Analyze" });
  expect((analyze as HTMLButtonElement).disabled).toBe(false);
  await user.click(analyze);
  expect(await screen.findByText("Canned summary for interaction tests.")).toBeTruthy();
});

test("rate-limited analysis shows retry-after guidance", async () => {
  stubFetch(
    () =>
      new Response(
        JSON.stringify({
          detail: { code: "rate_limited", message: "Too many requests." },
        }),
        {
          status: 429,
          headers: { "Content-Type": "application/json", "Retry-After": "45" },
        },
      ),
  );
  const user = userEvent.setup();
  await renderApp();
  await user.upload(
    fileInput(),
    new File(["x"], "r.txt", { type: "text/plain" }),
  );
  await user.click(screen.getByRole("button", { name: "Analyze" }));
  expect(await screen.findByText("Too many requests — rate limited.")).toBeTruthy();
  expect(screen.getByText("Wait 45 seconds, then retry.")).toBeTruthy();
});

test("missing server-side acknowledgment points back to the notice", async () => {
  stubFetch(() =>
    jsonResponse(
      {
        detail: {
          code: "consent_required",
          message: "AI processing acknowledgment is required before analysis.",
        },
      },
      403,
    ),
  );
  const user = userEvent.setup();
  await renderApp();
  await user.upload(
    fileInput(),
    new File(["x"], "r.txt", { type: "text/plain" }),
  );
  await user.click(screen.getByRole("button", { name: "Analyze" }));
  expect(
    await screen.findByText("External AI processing not acknowledged."),
  ).toBeTruthy();
  expect(screen.getByText(/acknowledgment checkbox/)).toBeTruthy();
});
