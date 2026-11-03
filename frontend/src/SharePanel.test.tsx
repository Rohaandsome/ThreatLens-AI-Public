/** Interaction tests for the Share Intelligence workflow. */

import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import SharePanel from "./components/SharePanel";

const RESULT = {
  filename: "r.txt",
  file_type: "txt",
  char_count: 42,
  truncated: false,
  model: "muse-spark-1.3",
  warnings: [],
  analysis: {
    executive_summary: "Summary for share tests.",
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
      {
        value: "198.51.100.23",
        type: "ip",
        context: "",
        evidence_quote: "",
        verified_in_source: false,
      },
    ],
    cves: [
      {
        id: "CVE-2026-44107",
        description: "",
        evidence_quote: "of CVE-2026-44107",
        verified_in_source: true,
      },
    ],
    affected_systems: [
      {
        system: "BM-ENG-WS04",
        detail: "owned",
        evidence_quote: "owned",
        inferred: false,
      },
    ],
    recommendations: [
      { recommendation: "Isolate host.", priority: "critical", rationale: "" },
    ],
    supporting_evidence: [{ quote: "opened the attachment", relevance: "access" }],
  },
} as const;

function packageResponse(overrides: Record<string, unknown> = {}) {
  return {
    package_id: "pkg1234567890",
    classification: {
      source_markings: ["TLP:AMBER"],
      effective_source: "TLP:AMBER",
      proposed: "TLP:AMBER",
      downgrade: false,
      analyst_asserted: false,
    },
    audience: "Limited disclosure: the recipient's organization and its clients.",
    audience_note: "",
    content: (RESULT as unknown as { analysis: unknown }).analysis,
    content_counts: {
      summary: 1,
      techniques: 1,
      iocs: 2,
      cves: 1,
      systems: 1,
      recommendations: 1,
      evidence: 1,
    },
    warnings: ["Included IOC '198.51.100.23' is unverified against the source."],
    redactions_applied: 0,
    audit_id: "audit1234567890",
    ...overrides,
  };
}

let fetchMock: ReturnType<typeof vi.fn>;

const STIX_BUNDLE = {
  filename: "threatlens-r-ab12cd34.stix.json",
  media_type: "application/json",
  bundle: { type: "bundle", id: "bundle--1", objects: [] },
  warnings: [],
  object_counts: { identity: 1, report: 1, "marking-definition": 1 },
};

function stubPrepare(
  impl?: () => Response,
  pdfImpl?: () => Response,
  stixImpl?: () => Response,
) {
  fetchMock = vi.fn(async (url: string | URL | Request) => {
    const target = String(url);
    if (target.includes("/api/share/pdf")) {
      return pdfImpl
        ? pdfImpl()
        : new Response("%PDF-fake-bytes", {
            status: 200,
            headers: { "Content-Type": "application/pdf" },
          });
    }
    if (target.includes("/api/share/stix")) {
      return stixImpl
        ? stixImpl()
        : new Response(JSON.stringify(STIX_BUNDLE), { status: 200 });
    }
    return impl ? impl() : new Response(JSON.stringify(packageResponse()), { status: 200 });
  });
  vi.stubGlobal("fetch", fetchMock);
}

beforeEach(() => {
  stubPrepare();
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

async function fillValidForm(user: ReturnType<typeof userEvent.setup>) {
  await user.selectOptions(
    screen.getByLabelText("Analyst classification (required when any source is unmarked)"),
    "TLP:AMBER",
  );
  await user.click(screen.getByRole("radio", { name: "Proposed marking TLP:AMBER" }));
  await user.click(screen.getByRole("checkbox", { name: /I have reviewed/ }));
}

test("unmarked source shows review-required and blocks preparation", async () => {
  const user = userEvent.setup();
  render(<SharePanel result={RESULT as never} role="analyst" onClose={() => {}} />);
  expect(screen.getByText(/UNCLASSIFIED — REVIEW REQUIRED/)).toBeTruthy();
  expect(
    (screen.getByRole("button", { name: /prepare package/i }) as HTMLButtonElement)
      .disabled,
  ).toBe(true);

  await fillValidForm(user);
  expect(screen.queryByText(/UNCLASSIFIED — REVIEW REQUIRED/)).toBeNull();
  expect(
    (screen.getByRole("button", { name: /prepare package/i }) as HTMLButtonElement)
      .disabled,
  ).toBe(false);
});

test("prepare shows preview with classification, audience, and warnings", async () => {
  const user = userEvent.setup();
  const realCreate = URL.createObjectURL;
  const realRevoke = URL.revokeObjectURL;
  URL.createObjectURL = (() => "blob:fake") as typeof URL.createObjectURL;
  URL.revokeObjectURL = (() => {}) as typeof URL.revokeObjectURL;
  const anchorClick = vi
    .spyOn(HTMLAnchorElement.prototype, "click")
    .mockImplementation(() => {});
  try {
    render(<SharePanel result={RESULT as never} role="analyst" onClose={() => {}} />);
    await fillValidForm(user);
    await user.click(screen.getByRole("button", { name: /prepare package/i }));

    await screen.findByText("Prepared package — preview");
    expect(screen.getByText("TLP:AMBER → TLP:AMBER")).toBeTruthy();
    expect(screen.getByText(/recipient's organization and its clients/)).toBeTruthy();
    expect(screen.getByText(/198\.51\.100\.23.*unverified/)).toBeTruthy();
    expect(screen.getByText("192.0.2.44")).toBeTruthy();

    const [, opts] = fetchMock.mock.calls[0] as [string, RequestInit];
    const sent = JSON.parse(opts.body as string) as {
      selection: { iocs: string[] };
      approval: { approved: boolean; analyst: string };
    };
    expect(sent.selection.iocs).toEqual(["192.0.2.44", "198.51.100.23"]);
    expect(sent.approval).toMatchObject({ approved: true, analyst: "" });

    await user.click(screen.getByRole("button", { name: /package json/i }));
    expect(anchorClick).toHaveBeenCalledTimes(1);
    const anchor = anchorClick.mock.instances[0] as HTMLAnchorElement;
    expect(anchor.download).toMatch(/threatlens-share-.*\.json/);
  } finally {
    URL.createObjectURL = realCreate;
    URL.revokeObjectURL = realRevoke;
  }
});

test("deselected findings are excluded from the request", async () => {
  const user = userEvent.setup();
  render(<SharePanel result={RESULT as never} role="analyst" onClose={() => {}} />);
  await fillValidForm(user);
  await user.click(screen.getByRole("checkbox", { name: "Include IOC 198.51.100.23" }));
  await user.click(screen.getByRole("button", { name: /prepare package/i }));
  await screen.findByText("Prepared package — preview");

  const [, opts] = fetchMock.mock.calls[0] as [string, RequestInit];
  const sent = JSON.parse(opts.body as string) as {
    selection: { iocs: string[] };
  };
  expect(sent.selection.iocs).toEqual(["192.0.2.44"]);
});

test("redactions are sent with the request", async () => {
  const user = userEvent.setup();
  render(<SharePanel result={RESULT as never} role="analyst" onClose={() => {}} />);
  await fillValidForm(user);
  await user.click(screen.getByRole("button", { name: /add redaction/i }));
  await user.type(screen.getByLabelText("Redaction 1 match"), "BM-ENG-WS04");
  await user.type(screen.getByLabelText("Redaction 1 replacement"), "[[HOST-1]");
  await user.click(screen.getByRole("button", { name: /prepare package/i }));
  await screen.findByText("Prepared package — preview");

  const [, opts] = fetchMock.mock.calls[0] as [string, RequestInit];
  const sent = JSON.parse(opts.body as string) as {
    redactions: { match: string; replacement: string }[];
  };
  expect(sent.redactions).toEqual([{ match: "BM-ENG-WS04", replacement: "[HOST-1]" }]);
});

test("backend downgrade rejection renders a friendly error", async () => {
  stubPrepare(
    () =>
      new Response(
        JSON.stringify({
          detail: {
            code: "downgrade_attempt",
            message: "Downgrade requires explicit acceptance and a justification.",
          },
        }),
        { status: 422 },
      ),
  );
  const user = userEvent.setup();
  render(<SharePanel result={RESULT as never} role="analyst" onClose={() => {}} />);
  await fillValidForm(user);
  await user.click(screen.getByRole("button", { name: /prepare package/i }));
  expect(await screen.findByText("Downgrade blocked.")).toBeTruthy();
  await user.click(screen.getByRole("button", { name: /back to review/i }));
  expect(screen.getByRole("button", { name: /prepare package/i })).toBeTruthy();
});

test("analyst notes are sent with the prepare request", async () => {
  const user = userEvent.setup();
  render(<SharePanel result={RESULT as never} role="analyst" onClose={() => {}} />);
  await fillValidForm(user);
  await user.type(screen.getByLabelText(/Notes for recipients/), "Call the duty officer.");
  await user.click(screen.getByRole("button", { name: /prepare package/i }));
  await screen.findByText("Prepared package — preview");

  const [, opts] = fetchMock.mock.calls[0] as [string, RequestInit];
  const sent = JSON.parse(opts.body as string) as { analyst_notes: string };
  expect(sent.analyst_notes).toBe("Call the duty officer.");
});

test("pdf download posts the package and saves the report", async () => {
  const user = userEvent.setup();
  const realCreate = URL.createObjectURL;
  const realRevoke = URL.revokeObjectURL;
  URL.createObjectURL = (() => "blob:fake") as typeof URL.createObjectURL;
  URL.revokeObjectURL = (() => {}) as typeof URL.revokeObjectURL;
  const anchorClick = vi
    .spyOn(HTMLAnchorElement.prototype, "click")
    .mockImplementation(() => {});
  try {
    render(<SharePanel result={RESULT as never} role="analyst" onClose={() => {}} />);
    await fillValidForm(user);
    await user.click(screen.getByRole("button", { name: /prepare package/i }));
    await screen.findByText("Prepared package — preview");

    await user.click(screen.getByRole("button", { name: /pdf report/i }));
    await vi.waitFor(() => expect(anchorClick).toHaveBeenCalledTimes(1));

    const call = fetchMock.mock.calls.find(([url]) => url === "/api/share/pdf");
    expect(call).toBeTruthy();
    const [, opts] = call as [string, RequestInit];
    const sent = JSON.parse(opts.body as string) as {
      package: { package_id: string };
      analyst: string;
    };
    expect(sent.package.package_id).toBe("pkg1234567890");
    expect(sent.analyst).toBe("");
    const anchor = anchorClick.mock.instances[0] as HTMLAnchorElement;
    expect(anchor.download).toBe("threatlens-share-pkg12345.pdf");
  } finally {
    URL.createObjectURL = realCreate;
    URL.revokeObjectURL = realRevoke;
  }
});

test("stix download posts the package and saves the bundle", async () => {
  const user = userEvent.setup();
  const realCreate = URL.createObjectURL;
  const realRevoke = URL.revokeObjectURL;
  URL.createObjectURL = (() => "blob:fake") as typeof URL.createObjectURL;
  URL.revokeObjectURL = (() => {}) as typeof URL.revokeObjectURL;
  const anchorClick = vi
    .spyOn(HTMLAnchorElement.prototype, "click")
    .mockImplementation(() => {});
  try {
    render(<SharePanel result={RESULT as never} role="analyst" onClose={() => {}} />);
    await fillValidForm(user);
    await user.click(screen.getByRole("button", { name: /prepare package/i }));
    await screen.findByText("Prepared package — preview");

    await user.click(screen.getByRole("button", { name: /stix bundle/i }));
    await screen.findByText(/STIX bundle: 3 objects/);

    const call = fetchMock.mock.calls.find(([url]) => url === "/api/share/stix");
    expect(call).toBeTruthy();
    expect(anchorClick).toHaveBeenCalledTimes(1);
    const anchor = anchorClick.mock.instances[0] as HTMLAnchorElement;
    expect(anchor.download).toBe("threatlens-r-ab12cd34.stix.json");
  } finally {
    URL.createObjectURL = realCreate;
    URL.revokeObjectURL = realRevoke;
  }
});

test("downgrade requires justification before preparing", async () => {
  const user = userEvent.setup();
  render(<SharePanel result={RESULT as never} role="analyst" onClose={() => {}} />);
  await user.selectOptions(
    screen.getByLabelText("Analyst classification (required when any source is unmarked)"),
    "TLP:AMBER",
  );
  await user.click(
    screen.getByRole("radio", { name: "Proposed marking TLP:GREEN" }),
  );
  expect(screen.getByText(/DOWNGRADE: TLP:AMBER → TLP:GREEN/)).toBeTruthy();
  await user.click(screen.getByRole("checkbox", { name: /I have reviewed/ }));
  // Still blocked: no downgrade acceptance or justification.
  expect(
    (screen.getByRole("button", { name: /prepare package/i }) as HTMLButtonElement)
      .disabled,
  ).toBe(true);
  await user.click(screen.getByRole("checkbox", { name: /explicitly accept this downgrade/i }));
  await user.type(
    screen.getByLabelText(/Downgrade justification/),
    "IOCs only for the community ISAC.",
  );
  expect(
    (screen.getByRole("button", { name: /prepare package/i }) as HTMLButtonElement)
      .disabled,
  ).toBe(false);
});
