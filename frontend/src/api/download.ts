/** Trigger a browser download of a Blob. */

export function downloadBlob(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Trigger a browser download of a JSON payload. */

export function downloadJson(filename: string, payload: unknown) {
  downloadBlob(
    filename,
    new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }),
  );
}
