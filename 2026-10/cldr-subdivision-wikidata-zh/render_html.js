#!/usr/bin/env node
"use strict";

const fs = require("node:fs/promises");
const path = require("node:path");
const cldrData = require("cldr-subdivisions-full/subdivisions/en/en.json");

const LANGUAGES = ["en", "zh-cn", "zh", "zh-tw"];
const HEADERS = ["item", "label", "code", "codeLabel"];
const INPUT = path.join(__dirname, "wikiSubdivisionLanguages.csv");
const OUTPUT = path.join(__dirname, "wikiSubdivisionLanguages.html");
const UPSTREAM_QUERY = "https://github.com/unicode-org/cldr/blob/main/tools/cldr-rdf/src/main/resources/org/unicode/cldr/rdf/sparql/wikidata-wikisubdivisionLanguages.sparql";
const CLDR_NAMES = cldrData.subdivisions.localeDisplayNames.subdivisions;

function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = "";
  let quoted = false;
  text = text.replace(/^\uFEFF/, "");

  for (let i = 0; i < text.length; i += 1) {
    const character = text[i];
    if (quoted) {
      if (character === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 1;
        } else {
          quoted = false;
        }
      } else {
        field += character;
      }
    } else if (character === '"' && field === "") {
      quoted = true;
    } else if (character === ",") {
      row.push(field);
      field = "";
    } else if (character === "\n" || character === "\r") {
      if (character === "\r" && text[i + 1] === "\n") i += 1;
      row.push(field);
      if (row.some((value) => value !== "")) rows.push(row);
      row = [];
      field = "";
    } else {
      field += character;
    }
  }

  if (quoted) throw new Error("CSV ends inside a quoted field");
  if (field !== "" || row.length > 0) {
    row.push(field);
    if (row.some((value) => value !== "")) rows.push(row);
  }
  return rows;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

function codeToCldrKey(code) {
  return code.toLowerCase().replace(/-/g, "");
}

function mergeableNames(values) {
  const cells = [];
  for (let start = 0; start < values.length;) {
    let end = start + 1;
    while (end < values.length && values[end] === values[start]) end += 1;
    cells.push({ value: values[start], colspan: end - start });
    start = end;
  }
  return cells;
}

function compareEnglishNames(wikidataName, cldrName) {
  if (!wikidataName || !wikidataName.trim()) return null;
  const wikidata = wikidataName.normalize("NFC").trim().toLocaleLowerCase("en");
  const cldr = cldrName.normalize("NFC").trim().toLocaleLowerCase("en");
  if (wikidata === cldr) return { same: true };
  if (wikidata.length < cldr.length && (cldr.startsWith(wikidata) || cldr.endsWith(wikidata))) {
    return { shorter: "wikidata" };
  }
  if (cldr.length < wikidata.length && (wikidata.startsWith(cldr) || wikidata.endsWith(cldr))) {
    return { shorter: "cldr" };
  }
  return null;
}

function renderRows(csvRows) {
  if (!csvRows.length || HEADERS.some((header, i) => csvRows[0][i] !== header)) {
    throw new Error(`CSV header must be ${HEADERS.join(",")}`);
  }

  const subdivisions = new Map();
  let skipped = 0;
  for (const values of csvRows.slice(1)) {
    if (values.length !== HEADERS.length) {
      throw new Error(`Expected ${HEADERS.length} CSV fields, got ${values.length}`);
    }
    const [item, label, code, language] = values;
    const cldrName = CLDR_NAMES[codeToCldrKey(code)];
    if (typeof cldrName !== "string") {
      skipped += 1;
      continue;
    }

    const key = `${code}\u0000${item}`;
    let subdivision = subdivisions.get(key);
    if (!subdivision) {
      subdivision = { item, code, cldrName, names: {} };
      subdivisions.set(key, subdivision);
    }
    if (LANGUAGES.includes(language)) subdivision.names[language] = label;
  }
  return {
    rows: [...subdivisions.values()].sort((a, b) => a.code.localeCompare(b.code) || a.item.localeCompare(b.item)),
    skipped,
  };
}

function renderHtml(rows) {
  const lines = [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    "<title>Wikidata and CLDR subdivision names</title>",
    "<style>th:nth-child(n+3), td:nth-child(n+3) { text-align: center; } td.merged { background-color: #fff2cc; border: 1px solid #d6b656; } td.near-match { background-color: #fff8e6; border: 1px solid #e7ddb8; }</style>",
    "</head>",
    "<body>",
    "<table>",
    `<caption>Wikidata subdivision labels; <a href="${UPSTREAM_QUERY}">upstream CLDR query</a></caption>`,
    "<thead><tr><th>item</th><th>code</th><th>name_en_wikidata</th><th>name_en_cldr</th><th>name_zh-cn</th><th>name_zh</th><th>name_zh-tw</th></tr></thead>",
    "<tbody>",
  ];

  for (const subdivision of rows) {
    const { item, code, cldrName, names } = subdivision;
    const itemId = item.slice(item.lastIndexOf("/") + 1);
    const wikidataEnglishName = names.en || "";
    const wikidataEnglish = wikidataEnglishName || "N/A";
    const englishMatch = compareEnglishNames(wikidataEnglishName, cldrName);
    const zhNames = ["zh-cn", "zh", "zh-tw"].map((language) => names[language] || "N/A");
    lines.push("<tr>");
    lines.push(`<td><a href="${escapeHtml(item)}">${escapeHtml(itemId)}</a></td>`);
    lines.push(`<td>${escapeHtml(code)}</td>`);

    if (englishMatch?.same) {
      lines.push(`<td class="merged" colspan="2">${escapeHtml(cldrName)}</td>`);
    } else {
      const wikidataClass = englishMatch?.shorter === "wikidata" ? ' class="near-match" title="Shorter prefix/suffix match"' : "";
      const cldrClass = englishMatch?.shorter === "cldr" ? ' class="near-match" title="Shorter prefix/suffix match"' : "";
      lines.push(`<td${wikidataClass}>${escapeHtml(wikidataEnglish)}</td>`);
      lines.push(`<td${cldrClass}>${escapeHtml(cldrName)}</td>`);
    }

    for (const cell of mergeableNames(zhNames)) {
      const merged = cell.colspan > 1 ? ' class="merged"' : "";
      const span = cell.colspan > 1 ? ` colspan="${cell.colspan}"` : "";
      lines.push(`<td${merged}${span}>${escapeHtml(cell.value)}</td>`);
    }
    lines.push("</tr>");
  }

  lines.push("</tbody>", "</table>", "</body>", "</html>", "");
  return lines.join("\n");
}

async function main() {
  const input = process.argv[2] ? path.resolve(process.argv[2]) : INPUT;
  const output = process.argv[3] ? path.resolve(process.argv[3]) : OUTPUT;
  const csvRows = parseCsv(await fs.readFile(input, "utf8"));
  const { rows, skipped } = renderRows(csvRows);
  await fs.writeFile(output, renderHtml(rows), "utf8");
  console.log(`Wrote ${rows.length} HTML rows to ${output}; skipped ${skipped} CSV rows without a CLDR code`);
}

main().catch((error) => {
  console.error(`HTML generation failed: ${error.message}`);
  process.exitCode = 1;
});
