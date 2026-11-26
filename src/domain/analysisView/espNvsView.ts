import { z } from "zod";
import { espNvsReportSchema } from "../firmware/espNvs.js";
import { ok } from "../result.js";
import type { AnalysisViewParent } from "./analysisViewParent.js";
import {
  assertOwnedView,
  type AdmittedView,
  type SummaryAnalysisView,
} from "./analysisViewShape.js";
import { invalidAnalysisView } from "./analysisViewErrors.js";
import { createAnalysisViewResultReader } from "./analysisViewParent.js";
import {
  boundedViewMessages,
  completeWithinViewCoverage,
  pageViewCoverage,
} from "./analysisViewCoverage.js";

export const espNvsViewRequestSchema = z.strictObject({
  kind: z.literal("esp-nvs"),
  collection: z.enum(["entries", "pages", "namespaces", "anomalies"]),
  namespace: z
    .string()
    .optional()
    .describe(
      "Exact NVS namespace name filter; supported only for the entries collection",
    ),
  offset: z.int().nonnegative().default(0),
  limit: z.int().positive().max(1024).default(64),
});

const sourceIndex = { source_index: z.int().nonnegative() };

export const espNvsViewItemsSchema = z.union([
  z.array(espNvsReportSchema.shape.entries.element.extend(sourceIndex)),
  z.array(espNvsReportSchema.shape.pages.element.extend(sourceIndex)),
  z.array(espNvsReportSchema.shape.namespaces.element.extend(sourceIndex)),
  z.array(
    z.strictObject({
      anomaly: z.string(),
      ...sourceIndex,
    }),
  ),
]);

const {
  artifact,
  partition_range,
  coverage,
  namespaces,
  corrupt_entry_count,
  corrupt_or_encrypted_page_count,
} = espNvsReportSchema.shape;

const counts = {
  page_count: z.int().nonnegative(),
  namespace_count: z.int().nonnegative(),
  entry_count: z.int().nonnegative(),
  corrupt_entry_count,
  corrupt_or_encrypted_page_count,
  anomaly_count: z.int().nonnegative(),
};

export const espNvsSummarySchema = z.strictObject({
  artifact,
  partition_range,
  coverage,
  namespaces,
  ...counts,
});

export const espNvsPageContextSchema = z.strictObject({
  artifact,
  partition_range,
  coverage,
  ...counts,
});

const readReport = createAnalysisViewResultReader(espNvsReportSchema);

export const projectEspNvsView = (
  parent: AnalysisViewParent,
  view: AdmittedView,
) => {
  if (view.kind !== "summary" && view.kind !== "esp-nvs")
    return invalidAnalysisView(
      "ESP-IDF NVS Evidence supports summary and esp-nvs views.",
    );
  assertOwnedView<
    SummaryAnalysisView | z.output<typeof espNvsViewRequestSchema>
  >(view, "summary", "esp-nvs");
  const parsed = readReport(parent);
  if (!parsed.ok) return parsed;
  const r = parsed.value;
  const context = {
    artifact: r.artifact,
    partition_range: r.partition_range,
    coverage: r.coverage,
    page_count: r.pages.length,
    namespace_count: r.namespaces.length,
    entry_count: r.entries.length,
    corrupt_entry_count: r.corrupt_entry_count,
    corrupt_or_encrypted_page_count: r.corrupt_or_encrypted_page_count,
    anomaly_count: r.anomalies.length,
  };
  const shared = {
    parent_evidence_id: parent.evidenceId,
    parent_operation: "inspect_esp_nvs" as const,
    parent_digest: parent.evidenceId.slice(3),
    artifact: { path: r.artifact.path, sha256: r.artifact.sha256 },
    limitations: boundedViewMessages(
      [...parent.limitations, ...r.limitations],
      parent.evidenceId,
      "limitations",
    ),
    unknowns: [
      "Encrypted NVS pages (XTS-AES with nvs_keys) cannot be decrypted without key material and remain classified as corrupt_or_encrypted.",
    ],
  };
  if (view.kind === "summary")
    return ok({
      ...shared,
      kind: "summary" as const,
      view,
      summary: { ...context, namespaces: r.namespaces },
      coverage: completeWithinViewCoverage(r.entries.length),
    });

  if (view.namespace !== undefined && view.collection !== "entries")
    return invalidAnalysisView(
      "namespace filters only the entries collection.",
    );

  if (view.collection === "entries") {
    const indexed =
      view.namespace === undefined
        ? r.entries.map((entry, idx) => ({ ...entry, source_index: idx }))
        : r.entries.flatMap((entry, idx) =>
            entry.namespace === view.namespace
              ? [{ ...entry, source_index: idx }]
              : [],
          );
    const items = indexed.slice(view.offset, view.offset + view.limit);
    return ok({
      ...shared,
      kind: "esp-nvs" as const,
      view,
      nvs: context,
      items,
      coverage: pageViewCoverage(view.offset, items.length, indexed.length),
    });
  }

  const page = <T>(rows: readonly T[]) => ({
    items: rows.slice(view.offset, view.offset + view.limit).map((row, i) => ({
      ...row,
      source_index: view.offset + i,
    })),
    total: rows.length,
  });

  const selected =
    view.collection === "pages"
      ? page(r.pages)
      : view.collection === "namespaces"
        ? page(r.namespaces)
        : {
            items: r.anomalies
              .slice(view.offset, view.offset + view.limit)
              .map((anomaly, i) => ({
                anomaly,
                source_index: view.offset + i,
              })),
            total: r.anomalies.length,
          };

  return ok({
    ...shared,
    kind: "esp-nvs" as const,
    view,
    nvs: context,
    items: selected.items,
    coverage: pageViewCoverage(
      view.offset,
      selected.items.length,
      selected.total,
    ),
  });
};
