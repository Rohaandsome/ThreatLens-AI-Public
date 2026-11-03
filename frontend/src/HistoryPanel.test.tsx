/** Interaction tests for the Sharing History + audit page (network mocked). */

import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import HistoryPanel from "./components/HistoryPanel";

const AUTH = { authenticated: false, role: "anonymous", distribution_enabled: false };

const RECORDS = [
  {
    id: "demo-006",
    report_id: "synthetic_relay_firmware.txt",
    package_id: "demo-pkg-0006",
    classification: "TLP:AMBER+STRICT",
    destination_kind: "misp",
    destination_label: "Your organisation only",
    destination_detail: { distribution: 0, sharing_group_id: null },
    findings: { iocs: 1, cves: 1, techniques: 1, systems: 4 },
    analyst: "demo-operator-3",
    approved_at: null,
    status: "pending_review",
    misp_event_uuid: null,
    error: null,
    demo: true,
    created_at: "2026-10-31T08:02:00+00:00",
    updated_at: "2026-10-31T08:02:00+00:00",
  },
  {
    id: "demo-001",
    report_id: "synthetic_ics_report.txt",
    package_id: "demo-pkg-0001",
    classification: "TLP:AMBER",
    destination_kind: "misp",
    destination_label: "Energy ISAC sharing group",
    destination_detail: { distribution: 4, sharing_group_id: 7 },
    findings: { iocs: 2, cves: 1, techniques: 2, systems: 2 },
    analyst: "demo-operator-1",
    approved_at: "2026-10-28T14:02:00+00:00",
    status: "published",
    misp_event_uuid: "11111111-1111-4111-8111-111111111111",
    error: null,
    demo: true,
    created_at: "2026-10-28T13:55:00+00:00",
    updated_at: "2026-10-28T14:02:00+00:00",
  },
];

const HISTORY = {
  records: RECORDS,
  total: 2,
  demo: true,
  distribution_enabled: false,
};

const AUDIT = {
  events: [
    {
      id: "a2",
      ts: "2026-10-31T10:00:00+00:00",
      event: "distribution_denied",
      action: "send",
      record_id: "demo-006",
      role: "anonymous",
    },
    {
      id: "a1",
      ts: "2026-10-31T09:00:00+00:00",
      event: "prepared",
      package_id: "pkg-1",
    },
  ],
  total: 2,
};

let fetchMock: ReturnType<typeof vi.fn>;
let routes: Record<string, () => Response>;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

function stub(overrides: Record<string, () => Response> = {}) {
  routes = {
    "/api/auth/status": () => json(AUTH),
    "/api/history/records": () => json(HISTORY),
    "/api/audit/events": () => json(AUDIT),
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

function historyUrls(): string[] {
  return fetchMock.mock.calls
    .map((args: unknown[]) => String(args[0]))
    .filter((u) => u.includes("/api/history/records"));
}

test("shows demo banner, auth status, and record fields", async () => {
  render(<HistoryPanel />);
  expect(await screen.findByText(/DEMONSTRATION DATA/)).toBeTruthy();
  expect(screen.getByText(/ROLE: ANONYMOUS/)).toBeTruthy();
  expect(screen.getByText(/DISTRIBUTION: DISABLED/)).toBeTruthy();
  expect(screen.getByText("synthetic_relay_firmware.txt")).toBeTruthy();
  const table = screen.getByRole("table");
  expect(within(table).getByText("TLP:AMBER+STRICT")).toBeTruthy();
  expect(screen.getByText("Your organisation only")).toBeTruthy();
  expect(screen.getByText("1 IOC · 1 CVE · 1 TTP · 4 SYS")).toBeTruthy();
  expect(screen.getByText("pending_review")).toBeTruthy();
  expect(screen.getByText("11111111…")).toBeTruthy();
  expect(screen.getByText("2026-10-28 14:02")).toBeTruthy();
  expect(screen.getByText(/2 RECORD\(S\)/)).toBeTruthy();
});

test("mount fetches status and history with GETs only", async () => {
  render(<HistoryPanel />);
  await screen.findByText("synthetic_relay_firmware.txt");
  const urls = fetchMock.mock.calls.map((args: unknown[]) => String(args[0]));
  expect(urls).toHaveLength(2);
  expect(urls.some((u) => u.includes("/api/auth/status"))).toBe(true);
  expect(urls.some((u) => u === "/api/history/records")).toBe(true);
  const methods = fetchMock.mock.calls.map(
    (args: unknown[]) => (args[1] as { method?: string } | undefined)?.method ?? "GET",
  );
  expect(methods).toEqual(["GET", "GET"]);
});

test("status tabs refetch with the status filter", async () => {
  const user = userEvent.setup();
  render(<HistoryPanel />);
  await screen.findByText("synthetic_relay_firmware.txt");
  await user.click(screen.getByRole("tab", { name: "MISP drafts" }));
  await screen.findByText("synthetic_relay_firmware.txt");
  const urls = historyUrls();
  expect(urls[urls.length - 1]).toContain("status=draft");
  await user.click(screen.getByRole("tab", { name: "Pending review" }));
  expect(historyUrls()[historyUrls().length - 1]).toContain("status=pending_review");
});

test("apply filters sends classification, report, recipient, and dates", async () => {
  const user = userEvent.setup();
  render(<HistoryPanel />);
  await screen.findByText("synthetic_relay_firmware.txt");
  await user.selectOptions(
    screen.getByLabelText("Filter by classification"),
    "TLP:AMBER",
  );
  await user.type(screen.getByLabelText("Filter by report"), "ics_report");
  await user.type(screen.getByLabelText("Filter by recipient"), "ISAC");
  fireEvent.change(screen.getByLabelText("Filter from date"), {
    target: { value: "2026-10-28" },
  });
  fireEvent.change(screen.getByLabelText("Filter to date"), {
    target: { value: "2026-10-30" },
  });
  await user.click(screen.getByRole("button", { name: "APPLY FILTERS" }));
  const last = historyUrls()[historyUrls().length - 1];
  expect(last).toContain("classification=TLP%3AAMBER");
  expect(last).toContain("report=ics_report");
  expect(last).toContain("recipient=ISAC");
  expect(last).toContain("since=2026-10-28T00%3A00%3A00");
  expect(last).toContain("until=2026-10-30T23%3A59%3A59");
});

test("clear resets filters and refetches unfiltered", async () => {
  const user = userEvent.setup();
  render(<HistoryPanel />);
  await screen.findByText("synthetic_relay_firmware.txt");
  await user.click(screen.getByRole("tab", { name: "Failed" }));
  await user.type(screen.getByLabelText("Filter by report"), "zzz");
  await user.click(screen.getByRole("button", { name: "CLEAR" }));
  const last = historyUrls()[historyUrls().length - 1];
  expect(last).toBe("/api/history/records");
});

test("expanding a row shows destination, analyst, and demo tag", async () => {
  const user = userEvent.setup();
  render(<HistoryPanel />);
  await user.click(await screen.findByText("synthetic_relay_firmware.txt"));
  expect(await screen.findByText(/demo-operator-3/)).toBeTruthy();
  expect(screen.getByText(/"distribution":0/)).toBeTruthy();
  expect(screen.getByText("DEMONSTRATION")).toBeTruthy();
});

test("distribution actions stay disabled and never call the API", async () => {
  const user = userEvent.setup();
  render(<HistoryPanel />);
  await screen.findByText("synthetic_relay_firmware.txt");
  const approve = screen.getByRole("button", {
    name: /APPROVE demo-006 \(disabled: requires authentication\)/,
  });
  expect((approve as HTMLButtonElement).disabled).toBe(true);
  expect(approve.getAttribute("title")).toContain("server-enforced");
  const before = fetchMock.mock.calls.length;
  await user.click(approve);
  expect(fetchMock.mock.calls.length).toBe(before);
  expect(
    fetchMock.mock.calls.map((args: unknown[]) => String(args[0])).join(" "),
  ).not.toContain("/api/distribution/");
});

test("audit tab lazy-loads and renders live events", async () => {
  const user = userEvent.setup();
  render(<HistoryPanel />);
  await screen.findByText("synthetic_relay_firmware.txt");
  expect(
    fetchMock.mock.calls.map((args: unknown[]) => String(args[0])).join(" "),
  ).not.toContain("/api/audit/events");
  await user.click(screen.getByRole("button", { name: /audit log/i }));
  expect(await screen.findByText(/LIVE AUDIT LOG/)).toBeTruthy();
  expect(screen.getByText("distribution_denied")).toBeTruthy();
  expect(screen.getByText(/action=send/)).toBeTruthy();
  expect(screen.getByText(/2 EVENT\(S\), NEWEST FIRST/)).toBeTruthy();
});

test("audit event filter is sent as a query param", async () => {
  const user = userEvent.setup();
  render(<HistoryPanel />);
  await screen.findByText("synthetic_relay_firmware.txt");
  await user.click(screen.getByRole("button", { name: /audit log/i }));
  await screen.findByText("distribution_denied");
  await user.type(screen.getByLabelText("Filter audit by event"), "prepared");
  await user.click(screen.getByRole("button", { name: "APPLY" }));
  const auditUrls = fetchMock.mock.calls
    .map((args: unknown[]) => String(args[0]))
    .filter((u) => u.includes("/api/audit/events"));
  expect(auditUrls[auditUrls.length - 1]).toContain("event=prepared");
});

test("history failure shows an error with retry", async () => {
  stub({
    "/api/history/records": () =>
      json({ detail: { code: "boom", message: "History exploded." } }, 500),
  });
  const user = userEvent.setup();
  render(<HistoryPanel />);
  expect(await screen.findByText(/History exploded/)).toBeTruthy();
  routes["/api/history/records"] = () => json(HISTORY);
  await user.click(screen.getByRole("button", { name: "Retry" }));
  expect(await screen.findByText("synthetic_relay_firmware.txt")).toBeTruthy();
});

test("empty history shows a no-match message", async () => {
  stub({
    "/api/history/records": () =>
      json({ records: [], total: 0, demo: true, distribution_enabled: false }),
  });
  render(<HistoryPanel />);
  expect(await screen.findByText(/No records match/)).toBeTruthy();
});
