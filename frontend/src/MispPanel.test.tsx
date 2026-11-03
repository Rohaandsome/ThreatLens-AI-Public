/** Interaction tests for the MISP export panel (all network mocked). */

import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import MispPanel from "./components/MispPanel";

const PKG = {
  package_id: "pkg1234567890",
  prepared_at: "2026-10-31T00:00:00Z",
  analyzed_at: null,
  source_filename: "r.txt",
  model: "muse-spark-1.3",
  classification: {
    source_markings: ["TLP:AMBER"],
    effective_source: "TLP:AMBER",
    proposed: "TLP:AMBER",
    downgrade: false,
    analyst_asserted: false,
  },
  audience: "audience",
  audience_note: "",
  analyst_notes: "",
  content: {},
  content_counts: {},
  warnings: [],
  redactions_applied: 0,
  audit_id: "audit1",
};

const TEST_OK = {
  ok: true,
  url: "https://misp.test",
  org: "Test Org",
  role: "analyst",
  can_add: true,
  can_publish: false,
  error: null,
};

const PREVIEW = {
  event: {
    info: "[ThreatLens] r.txt [TLP:AMBER]",
    distribution: 1,
    sharing_group_id: null,
    threat_level_id: 4,
    analysis: 2,
    published: false,
    tags: ["tlp:amber", 'misp-galaxy:mitre-attack-pattern="Valid Accounts - T1078"'],
    attributes: [
      {
        type: "ip-dst",
        value: "192.0.2.44",
        category: "Network activity",
        to_ids: true,
        comment: "ctx",
      },
      {
        type: "text",
        value: "BM-ENG-WS04",
        category: "Other",
        to_ids: false,
        comment: "affected system (confirmed)",
      },
    ],
  },
  warnings: ["IOC '198.51.100.23' skipped (malformed)."],
  attribute_count: 2,
  tlp_tag: "tlp:amber",
  destination_check: {
    safe: true,
    reason: "Destination: This community only.",
    verified: false,
  },
};

const CREATED = {
  event_id: "42",
  event_uuid: "uuid-1",
  url: "https://misp.test/events/view/42",
  duplicate: false,
  warnings: [],
};

let fetchMock: ReturnType<typeof vi.fn>;
let routes: Record<string, () => Response>;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

function stub(overrides: Record<string, () => Response> = {}) {
  routes = {
    "/api/misp/test": () => json(TEST_OK),
    "/api/misp/preview": () => json(PREVIEW),
    "/api/misp/create": () => json(CREATED),
    "/api/misp/publish": () => json({ event_uuid: "uuid-1", published: true }),
    ...overrides,
  };
  fetchMock = vi.fn(async (url: string | URL | Request) => {
    const target = String(url);
    const key = Object.keys(routes).find((k) => target.includes(k));
    if (!key) throw new Error(`unexpected fetch: ${target}`);
    return routes[key]();
  });
  vi.stubGlobal("fetch", fetchMock);
}

beforeEach(() => {
  stub();
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderPanel(pkg: unknown = PKG, role = "administrator") {
  render(<MispPanel pkg={pkg as never} role={role} />);
}

function callsTo(path: string): Record<string, unknown>[] {
  return fetchMock.mock.calls
    .filter((args: unknown[]) => String(args[0]).includes(path))
    .map((args: unknown[]) => {
      const init = args[1] as { body?: string } | undefined;
      return init?.body ? (JSON.parse(init.body) as Record<string, unknown>) : {};
    });
}

test("renders without contacting any server", () => {
  renderPanel();
  expect(screen.getByText(/MISP EXPORT/)).toBeTruthy();
  expect(screen.getByRole("button", { name: /test connection/i })).toBeTruthy();
  expect(fetchMock).not.toHaveBeenCalled();
});

test("test connection shows org, role and permissions", async () => {
  const user = userEvent.setup();
  renderPanel();
  await user.click(screen.getByRole("button", { name: /test connection/i }));
  expect(await screen.findByText(/Test Org · analyst/)).toBeTruthy();
  expect(screen.getByText(/add:yes/)).toBeTruthy();
  expect(screen.getByText(/publish:no/)).toBeTruthy();
  expect(callsTo("/api/misp/test")).toHaveLength(1);
});

test("failed connection test points at backend env", async () => {
  stub({
    "/api/misp/test": () =>
      json({
        ok: false,
        url: "",
        org: "",
        role: "",
        can_add: false,
        can_publish: false,
        error: { code: "misp_not_configured", message: "MISP is not configured." },
      }),
  });
  const user = userEvent.setup();
  renderPanel();
  await user.click(screen.getByRole("button", { name: /test connection/i }));
  expect(await screen.findByText(/MISP is not configured/)).toBeTruthy();
  expect(screen.getByText(/backend\/.env/)).toBeTruthy();
});

test("preview shows tags, attributes and warnings", async () => {
  const user = userEvent.setup();
  renderPanel();
  await user.click(screen.getByRole("radio", { name: /This community only/ }));
  await user.click(screen.getByRole("button", { name: /preview event/i }));
  expect(await screen.findByText("[ThreatLens] r.txt [TLP:AMBER]")).toBeTruthy();
  expect(screen.getByText(/tlp:amber/)).toBeTruthy();
  expect(screen.getByText("192.0.2.44")).toBeTruthy();
  expect(screen.getByText("BM-ENG-WS04")).toBeTruthy();
  expect(screen.getByText(/skipped \(malformed\)/)).toBeTruthy();
  expect(screen.getByText(/THIS COMMUNITY ONLY/)).toBeTruthy();
  const bodies = callsTo("/api/misp/preview");
  expect(bodies).toHaveLength(1);
  expect(bodies[0]["destination"]).toEqual({
    distribution: 1,
    sharing_group_id: null,
  });
});

test("create needs approval, confirmation and a current preview", async () => {
  const user = userEvent.setup();
  renderPanel();
  const create = screen.getByRole("button", { name: /create draft/i });
  expect((create as HTMLButtonElement).disabled).toBe(true);

  await user.click(screen.getByRole("checkbox", { name: /Approve MISP draft/ }));
  await user.click(screen.getByRole("checkbox", { name: /Confirm MISP destination/ }));
  expect((create as HTMLButtonElement).disabled).toBe(true); // no preview yet

  await user.click(screen.getByRole("button", { name: /preview event/i }));
  await screen.findByText("[ThreatLens] r.txt [TLP:AMBER]");
  expect((create as HTMLButtonElement).disabled).toBe(false);

  await user.click(create);
  expect(await screen.findByText(/Draft created \(unpublished\)/)).toBeTruthy();
  const link = screen.getByRole("link", { name: /open event/i });
  expect(link.getAttribute("href")).toBe("https://misp.test/events/view/42");
  const bodies = callsTo("/api/misp/create");
  expect(bodies).toHaveLength(1);
  expect(bodies[0]["approval"]).toEqual({ approved: true, confirmed: true });
  expect(bodies[0]["analyst"]).toBe("");
});

test("duplicate draft is reported, not recreated silently", async () => {
  stub({ "/api/misp/create": () => json({ ...CREATED, duplicate: true }) });
  const user = userEvent.setup();
  renderPanel();
  await user.click(screen.getByRole("button", { name: /preview event/i }));
  await screen.findByText("[ThreatLens] r.txt [TLP:AMBER]");
  await user.click(screen.getByRole("checkbox", { name: /Approve MISP draft/ }));
  await user.click(screen.getByRole("checkbox", { name: /Confirm MISP destination/ }));
  await user.click(screen.getByRole("button", { name: /create draft/i }));
  expect(await screen.findByText(/already existed/)).toBeTruthy();
});

test("create failure surfaces the backend message", async () => {
  stub({
    "/api/misp/create": () =>
      json(
        { detail: { code: "unsafe_destination", message: "TLP:RED may only stay home." } },
        403,
      ),
  });
  const user = userEvent.setup();
  renderPanel();
  await user.click(screen.getByRole("button", { name: /preview event/i }));
  await screen.findByText("[ThreatLens] r.txt [TLP:AMBER]");
  await user.click(screen.getByRole("checkbox", { name: /Approve MISP draft/ }));
  await user.click(screen.getByRole("checkbox", { name: /Confirm MISP destination/ }));
  await user.click(screen.getByRole("button", { name: /create draft/i }));
  expect(await screen.findByText(/TLP:RED may only stay home/)).toBeTruthy();
});

test("TLP:RED locks the destination to the creating organisation", async () => {
  const user = userEvent.setup();
  const red = {
    ...PKG,
    classification: { ...PKG.classification, proposed: "TLP:RED" },
  };
  renderPanel(red);
  expect(screen.getByText(/TLP:RED — drafts stay inside/)).toBeTruthy();
  const wide = screen.getByRole("radio", { name: /All communities/ });
  expect((wide as HTMLInputElement).disabled).toBe(true);
  const org = screen.getByRole("radio", { name: /Your organisation only/ });
  expect((org as HTMLInputElement).checked).toBe(true);

  await user.click(screen.getByRole("button", { name: /preview event/i }));
  await screen.findByText("[ThreatLens] r.txt [TLP:AMBER]");
  expect(callsTo("/api/misp/preview")[0]["destination"]).toEqual({
    distribution: 0,
    sharing_group_id: null,
  });
});

test("sharing group needs a numeric ID which is sent with the request", async () => {
  const user = userEvent.setup();
  renderPanel();
  await user.click(screen.getByRole("radio", { name: /Sharing group/ }));
  expect(screen.getByText(/positive numeric sharing-group ID/)).toBeTruthy();
  expect(
    (screen.getByRole("button", { name: /preview event/i }) as HTMLButtonElement)
      .disabled,
  ).toBe(true);
  await user.type(screen.getByLabelText("Sharing group ID"), "7");
  await user.click(screen.getByRole("button", { name: /preview event/i }));
  await screen.findByText("[ThreatLens] r.txt [TLP:AMBER]");
  expect(callsTo("/api/misp/preview")[0]["destination"]).toEqual({
    distribution: 4,
    sharing_group_id: 7,
  });
});

test("changing destination after preview forces a re-preview", async () => {
  const user = userEvent.setup();
  renderPanel();
  await user.click(screen.getByRole("button", { name: /preview event/i }));
  await screen.findByText("[ThreatLens] r.txt [TLP:AMBER]");
  await user.click(screen.getByRole("checkbox", { name: /Approve MISP draft/ }));
  await user.click(screen.getByRole("checkbox", { name: /Confirm MISP destination/ }));
  const create = screen.getByRole("button", { name: /create draft/i });
  expect((create as HTMLButtonElement).disabled).toBe(false);
  await user.click(screen.getByRole("radio", { name: /All communities/ }));
  expect(await screen.findByText(/preview again before/)).toBeTruthy();
  expect((create as HTMLButtonElement).disabled).toBe(true);
});

test("publish is locked until a draft exists, then needs three checkboxes", async () => {
  const user = userEvent.setup();
  renderPanel();
  expect(screen.getByText(/Create a draft first/)).toBeTruthy();
  expect(screen.queryByRole("button", { name: /publish event/i })).toBeNull();

  await user.click(screen.getByRole("button", { name: /preview event/i }));
  await screen.findByText("[ThreatLens] r.txt [TLP:AMBER]");
  await user.click(screen.getByRole("checkbox", { name: /Approve MISP draft/ }));
  await user.click(screen.getByRole("checkbox", { name: /Confirm MISP destination/ }));
  await user.click(screen.getByRole("button", { name: /create draft/i }));
  await screen.findByText(/Draft created/);

  const publish = screen.getByRole("button", { name: /publish event/i });
  expect((publish as HTMLButtonElement).disabled).toBe(true);
  await user.click(screen.getByRole("checkbox", { name: /Enable MISP publishing/ }));
  expect((publish as HTMLButtonElement).disabled).toBe(true);
  await user.click(screen.getByRole("checkbox", { name: /Approve MISP publishing/ }));
  await user.click(screen.getByRole("checkbox", { name: /Confirm MISP publishing/ }));
  expect((publish as HTMLButtonElement).disabled).toBe(false);
  await user.click(publish);
  expect(await screen.findByText(/Event published/)).toBeTruthy();
  const bodies = callsTo("/api/misp/publish");
  expect(bodies).toHaveLength(1);
  expect(bodies[0]["event_uuid"]).toBe("uuid-1");
  expect(bodies[0]["approval"]).toEqual({ approved: true, confirmed: true });
});

test("publish denial surfaces the backend message", async () => {
  stub({
    "/api/misp/publish": () =>
      json(
        {
          detail: {
            code: "permission_denied",
            message: "The MISP API user lacks permission to publish events.",
          },
        },
        403,
      ),
  });
  const user = userEvent.setup();
  renderPanel();
  await user.click(screen.getByRole("button", { name: /preview event/i }));
  await screen.findByText("[ThreatLens] r.txt [TLP:AMBER]");
  await user.click(screen.getByRole("checkbox", { name: /Approve MISP draft/ }));
  await user.click(screen.getByRole("checkbox", { name: /Confirm MISP destination/ }));
  await user.click(screen.getByRole("button", { name: /create draft/i }));
  await screen.findByText(/Draft created/);
  await user.click(screen.getByRole("checkbox", { name: /Enable MISP publishing/ }));
  await user.click(screen.getByRole("checkbox", { name: /Approve MISP publishing/ }));
  await user.click(screen.getByRole("checkbox", { name: /Confirm MISP publishing/ }));
  await user.click(screen.getByRole("button", { name: /publish event/i }));
  expect(await screen.findByText(/lacks permission to publish/)).toBeTruthy();
  expect(
    within(screen.getByLabelText("MISP export")).queryByText(/Event published/),
  ).toBeNull();
});

test("non-allowlisted destination denial surfaces on create", async () => {
  stub({
    "/api/misp/create": () =>
      json(
        {
          detail: {
            code: "destination_not_allowed",
            message: "Distribution 'All communities' is not in the allowlist.",
          },
        },
        403,
      ),
  });
  const user = userEvent.setup();
  renderPanel();
  await user.click(screen.getByRole("button", { name: /preview event/i }));
  await screen.findByText("[ThreatLens] r.txt [TLP:AMBER]");
  await user.click(screen.getByRole("checkbox", { name: /Approve MISP draft/ }));
  await user.click(screen.getByRole("checkbox", { name: /Confirm MISP destination/ }));
  await user.click(screen.getByRole("button", { name: /create draft/i }));
  expect(await screen.findByText(/not in the allowlist/)).toBeTruthy();
  expect(screen.getByText(/destination_not_allowed/)).toBeTruthy();
});

test("changed live destination blocks publish with re-preview guidance", async () => {
  stub({
    "/api/misp/publish": () =>
      json(
        {
          detail: {
            code: "destination_changed",
            message: "The live event no longer matches its approved destination.",
          },
        },
        403,
      ),
  });
  const user = userEvent.setup();
  renderPanel();
  await user.click(screen.getByRole("button", { name: /preview event/i }));
  await screen.findByText("[ThreatLens] r.txt [TLP:AMBER]");
  await user.click(screen.getByRole("checkbox", { name: /Approve MISP draft/ }));
  await user.click(screen.getByRole("checkbox", { name: /Confirm MISP destination/ }));
  await user.click(screen.getByRole("button", { name: /create draft/i }));
  await screen.findByText(/Draft created/);
  await user.click(screen.getByRole("checkbox", { name: /Enable MISP publishing/ }));
  await user.click(screen.getByRole("checkbox", { name: /Approve MISP publishing/ }));
  await user.click(screen.getByRole("checkbox", { name: /Confirm MISP publishing/ }));
  await user.click(screen.getByRole("button", { name: /publish event/i }));
  expect(await screen.findByText(/no longer matches the approved one/)).toBeTruthy();
  expect(
    within(screen.getByLabelText("MISP export")).queryByText(/Event published/),
  ).toBeNull();
});

test("unsafe preview check renders the allowlist reason", async () => {
  stub({
    "/api/misp/preview": () =>
      json({
        ...PREVIEW,
        destination_check: {
          safe: false,
          reason: "Sharing group 9 is not in the MISP destination allowlist.",
          verified: false,
        },
      }),
  });
  const user = userEvent.setup();
  renderPanel();
  await user.click(screen.getByRole("button", { name: /preview event/i }));
  expect(await screen.findByText(/not in the MISP destination allowlist/)).toBeTruthy();
});

test("operators see the administrator-only publish note", async () => {
  const user = userEvent.setup();
  renderPanel(PKG, "analyst");
  await user.click(screen.getByRole("button", { name: /preview event/i }));
  await screen.findByText("[ThreatLens] r.txt [TLP:AMBER]");
  await user.click(screen.getByRole("checkbox", { name: /Approve MISP draft/ }));
  await user.click(screen.getByRole("checkbox", { name: /Confirm MISP destination/ }));
  await user.click(screen.getByRole("button", { name: /create draft/i }));
  await screen.findByText(/Draft created/);
  expect(screen.getByText(/Requires administrator/)).toBeTruthy();
  expect(screen.queryByRole("button", { name: /publish event/i })).toBeNull();
  expect(
    fetchMock.mock.calls.map((args: unknown[]) => String(args[0])).join(" "),
  ).not.toContain("/api/misp/publish");
});
