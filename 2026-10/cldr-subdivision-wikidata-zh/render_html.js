#!/usr/bin/env node
"use strict";

const fs = require("node:fs/promises");
const path = require("node:path");
const OpenCC = require("opencc-js");
const cldrData = require("cldr-subdivisions-full/subdivisions/en/en.json");
const CLDR_COUNTRY_NAMES_EN = require("cldr-localenames-full/main/en/territories.json")
  .main.en.localeDisplayNames.territories;
const CLDR_COUNTRY_NAMES_ZH = require("cldr-localenames-full/main/zh/territories.json")
  .main.zh.localeDisplayNames.territories;

const LANGUAGES = ["en", "zh-cn", "zh", "zh-tw"];
const HEADERS = ["item", "label", "code", "codeLabel"];
const INPUT = path.join(__dirname, "wikiSubdivisionLanguages.csv");
const OUTPUT = path.join(__dirname, "wikiSubdivisionLanguages.html");
const MCA_NAMES_INPUT = path.join(__dirname, "mca_subdivisions_zh.json");
const CHINESE_LANGUAGES = ["zh-cn", "zh", "zh-tw"];
const IGNORED_TERMINAL_SUFFIXES = {
  AU: ["州"],
  IT: ["首都广域市", "广域市", "大区", "区", "省"],
  JP: ["县"],
  MX: ["州"],
  MY: ["州"],
  TH: ["府"],
  US: ["州"],
};
const UPSTREAM_QUERY = "https://github.com/unicode-org/cldr/blob/main/tools/cldr-rdf/src/main/resources/org/unicode/cldr/rdf/sparql/wikidata-wikisubdivisionLanguages.sparql";
const MCA_DATABASE_URL = "https://dmfw.mca.gov.cn/foreign.html";
const CLDR_NAMES = cldrData.subdivisions.localeDisplayNames.subdivisions;
const CLDR_CONTAINMENT = require("cldr-core/supplemental/subdivisionContainment.json").supplemental.subdivisionContainment;

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

function normalize(value, country, convert) {
  let text = convert(String(value ?? "").normalize("NFKC"));
  text = text.replace(/\p{Pd}/gu, "-").replace(/洲/gu, "州");
  text = text.replace(/[（(][^）)]*[）)]/gu, "");
  const suffixes = [...(IGNORED_TERMINAL_SUFFIXES[country] || [])]
    .sort((left, right) => right.length - left.length);
  if (suffixes.length) {
    text = text.replace(new RegExp(`(?:${suffixes.join("|")})+$`, "u"), "");
  }
  return text.replace(/\s+/gu, "");
}

function normalizeForms(value, country, convert) {
  const text = String(value ?? "").normalize("NFKC");
  const aliases = [...text.matchAll(/\(([^()]*)\)/gu)].map((match) => match[1]);
  const main = text.replace(/\([^()]*\)/gu, "");
  return new Set([main, ...aliases].map((candidate) => normalize(candidate, country, convert)).filter(Boolean));
}

function mcaAnnotationIndices(wikidataNames, mcaName, country, convert) {
  if (!mcaName) return new Set();
  const mcaForms = normalizeForms(mcaName, country, convert);
  const hasMatch = wikidataNames.some((name) => name !== "N/A" &&
    [...mcaForms].some((form) => normalizeForms(name, country, convert).has(form)));
  return hasMatch ? new Set() : new Set([0]);
}

function mergeableNames(values, annotations = new Set(), mcaName = "") {
  const cells = [];
  for (let start = 0; start < values.length;) {
    let end = start + 1;
    let marked = annotations.has(start);
    while (values[start] !== "N/A" && end < values.length && values[end] === values[start]) {
      marked ||= annotations.has(end);
      end += 1;
    }
    cells.push({ value: values[start], colspan: end - start, mcaName: marked ? mcaName : "" });
    start = end;
  }
  return cells;
}

async function loadMcaNames(file = MCA_NAMES_INPUT) {
  let document;
  try {
    document = JSON.parse(await fs.readFile(file, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") return {};
    throw error;
  }
  const names = document.subdivisions?.localeDisplayNames?.subdivisions;
  if (!names || typeof names !== "object" || Array.isArray(names)) {
    throw new Error(`${file} has no subdivisions.localeDisplayNames.subdivisions map`);
  }
  return names;
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

function splitLettersAndSeparators(value) {
  const letters = [];
  const separators = [[]];
  let index = 0;
  for (const character of Array.from(value)) {
    if (/\p{L}/u.test(character)) {
      letters.push(character.normalize("NFC").toLocaleLowerCase("en"));
      separators.push([]);
    } else if (/\p{M}/u.test(character) && letters.length) {
      const last = letters.length - 1;
      letters[last] = (letters[last] + character).normalize("NFC").toLocaleLowerCase("en");
    } else {
      separators[separators.length - 1].push({ character, index });
    }
    index += 1;
  }
  return { letters, separators };
}

function markSeparatorDifferences(left, right, leftHighlights, rightHighlights) {
  const lengths = Array.from({ length: left.length + 1 }, () => Array(right.length + 1).fill(0));
  for (let i = left.length - 1; i >= 0; i -= 1) {
    for (let j = right.length - 1; j >= 0; j -= 1) {
      lengths[i][j] = left[i].character === right[j].character
        ? lengths[i + 1][j + 1] + 1
        : Math.max(lengths[i + 1][j], lengths[i][j + 1]);
    }
  }

  let i = 0;
  let j = 0;
  while (i < left.length || j < right.length) {
    if (i < left.length && j < right.length && left[i].character === right[j].character) {
      i += 1;
      j += 1;
    } else if (j === right.length || (i < left.length && lengths[i + 1][j] >= lengths[i][j + 1])) {
      leftHighlights.add(left[i].index);
      i += 1;
    } else {
      rightHighlights.add(right[j].index);
      j += 1;
    }
  }
}

function nonAlphabeticDifference(wikidataName, cldrName) {
  if (!wikidataName || !wikidataName.trim()) return null;
  const wikidata = splitLettersAndSeparators(wikidataName);
  const cldr = splitLettersAndSeparators(cldrName);
  if (wikidata.letters.length !== cldr.letters.length ||
      wikidata.letters.some((letter, index) => letter !== cldr.letters[index])) return null;

  const wikidataHighlights = new Set();
  const cldrHighlights = new Set();
  for (let i = 0; i < wikidata.separators.length; i += 1) {
    const left = wikidata.separators[i];
    const right = cldr.separators[i];
    if (left.map((part) => part.character).join("") !== right.map((part) => part.character).join("")) {
      markSeparatorDifferences(left, right, wikidataHighlights, cldrHighlights);
    }
  }
  if (!wikidataHighlights.size && !cldrHighlights.size) return null;
  return { wikidata: [...wikidataHighlights], cldr: [...cldrHighlights] };
}

function singleCharacterDifference(wikidataName, cldrName) {
  if (!wikidataName || !wikidataName.trim()) return null;
  const wikidata = Array.from(wikidataName);
  const cldr = Array.from(cldrName);
  if (wikidata.length === cldr.length) {
    let index = -1;
    for (let i = 0; i < wikidata.length; i += 1) {
      if (wikidata[i] === cldr[i]) continue;
      if (index !== -1) return null;
      index = i;
    }
    return index === -1 ? null : { wikidata: [index], cldr: [index] };
  }

  if (wikidata.length + 1 === cldr.length) {
    let index = 0;
    while (index < wikidata.length && wikidata[index] === cldr[index]) index += 1;
    if (wikidata.slice(index).join("") === cldr.slice(index + 1).join("")) {
      return { wikidata: [], cldr: [index] };
    }
  } else if (cldr.length + 1 === wikidata.length) {
    let index = 0;
    while (index < cldr.length && wikidata[index] === cldr[index]) index += 1;
    if (wikidata.slice(index + 1).join("") === cldr.slice(index).join("")) {
      return { wikidata: [index], cldr: [] };
    }
  }
  return null;
}

function renderName(value, highlightIndices) {
  const highlights = new Set(highlightIndices || []);
  return Array.from(value)
    .map((character, index) => highlights.has(index)
      ? `<span class="near-match-char">${escapeHtml(character)}</span>`
      : escapeHtml(character))
    .join("");
}

function renderRows(csvRows) {
  if (!csvRows.length || HEADERS.some((header, i) => csvRows[0][i] !== header)) {
    throw new Error(`CSV header must be ${HEADERS.join(",")}`);
  }

  const subdivisions = new Map();
  const presentCodes = new Set();
  const countries = new Set();
  let skipped = 0;
  for (const values of csvRows.slice(1)) {
    if (values.length !== HEADERS.length) {
      throw new Error(`Expected ${HEADERS.length} CSV fields, got ${values.length}`);
    }
    const [item, label, code, language] = values;
    const country = code.match(/^([A-Z]{2})-/)?.[1];
    if (country) countries.add(country);
    const cldrName = CLDR_NAMES[codeToCldrKey(code)];
    if (typeof cldrName !== "string") {
      skipped += 1;
      continue;
    }

    presentCodes.add(code);
    const key = `${code}\u0000${item}`;
    let subdivision = subdivisions.get(key);
    if (!subdivision) {
      subdivision = { item, code, cldrName, names: {} };
      subdivisions.set(key, subdivision);
    }
    if (LANGUAGES.includes(language)) subdivision.names[language] = label;
  }
  let added = 0;
  for (const country of countries) {
    const visited = new Set();
    const addMissingDescendants = (parent) => {
      if (visited.has(parent)) return;
      visited.add(parent);
      for (const child of CLDR_CONTAINMENT[parent]?._contains || []) {
        if (Object.hasOwn(CLDR_NAMES, child)) {
          const code = `${country}-${child.slice(2).toUpperCase()}`;
          if (!presentCodes.has(code)) {
            subdivisions.set(`${code}\u0000`, { item: "", code, cldrName: CLDR_NAMES[child], names: {} });
            presentCodes.add(code);
            added += 1;
          }
        }
        addMissingDescendants(child);
      }
    };
    addMissingDescendants(country);
  }
  return {
    rows: [...subdivisions.values()].sort((a, b) => a.code.localeCompare(b.code) || a.item.localeCompare(b.item)),
    skipped,
    added,
  };
}

function renderHtml(rows, mcaNames = {}, convert = (value) => value) {
  const mcaSourceNote = Object.keys(mcaNames).length
    ? `. Selected territories with standardized translations from the <a href="${MCA_DATABASE_URL}">National Database for Geographical Names of China</a>`
    : "";
  const lines = [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    "<title>Wikidata and CLDR subdivision names</title>",
    "<style>th:nth-child(n+3), td:nth-child(n+3) { text-align: center; } tr.country-heading th { text-align: center; background-color: #f2f2f2; border-top: 2px solid #888; } td.merged { background-color: #fff2cc; border: 1px solid #d6b656; } td.near-match { background-color: #fff8e6; border: 1px solid #e7ddb8; } span.near-match-char { background-color: #e8b4b4; white-space: pre-wrap; } small.mca-label { display: block; font-size: 0.8em; margin-top: 0.15em; background-color: #e8b4b4; }</style>",
    "</head>",
    "<body>",
    "<table>",
    `<caption>Wikidata subdivision labels; <a href="${UPSTREAM_QUERY}">upstream CLDR query</a>${mcaSourceNote}</caption>`,
    "<thead><tr><th>item</th><th>code</th><th>name_en_cldr</th><th>name_en_wikidata</th><th>name_zh-cn</th><th>name_zh</th><th>name_zh-tw</th></tr></thead>",
    "<tbody>",
  ];

  const mcaCountries = new Set(Object.entries(mcaNames)
    .filter(([, name]) => typeof name === "string" && name.trim())
    .map(([key]) => key.slice(0, 2).toUpperCase()));
  let previousCountry = "";
  for (const subdivision of rows) {
    const { item, code, cldrName, names } = subdivision;
    const country = code.match(/^([A-Z]{2})-/)?.[1] || "";
    if (country && country !== previousCountry) {
      const countryNameEn = CLDR_COUNTRY_NAMES_EN[country];
      const countryNameZh = CLDR_COUNTRY_NAMES_ZH[country];
      if (!countryNameEn || !countryNameZh) throw new Error(`Missing CLDR country name for ${country}`);
      lines.push(`<tr class="country-heading"><th colspan="2">${escapeHtml(country)}</th><th colspan="2">${escapeHtml(countryNameEn)}</th><th colspan="3">${escapeHtml(countryNameZh)}</th></tr>`);
      previousCountry = country;
    }
    const itemId = item ? item.slice(item.lastIndexOf("/") + 1) : "";
    const wikidataEnglishName = names.en || "";
    const wikidataEnglish = wikidataEnglishName || "N/A";
    const englishMatch = compareEnglishNames(wikidataEnglishName, cldrName);
    const zhNames = CHINESE_LANGUAGES.map((language) => names[language] || "N/A");
    const mcaName = mcaNames[codeToCldrKey(code)];
    const hasMcaName = typeof mcaName === "string" && Boolean(mcaName.trim());
    const displayedMcaName = hasMcaName ? mcaName : mcaCountries.has(country) ? "N/A" : "";
    const annotations = hasMcaName
      ? mcaAnnotationIndices(zhNames, mcaName, country, convert)
      : displayedMcaName ? new Set([0]) : new Set();
    lines.push("<tr>");
    lines.push(item ? `<td><a href="${escapeHtml(item)}">${escapeHtml(itemId)}</a></td>` : "<td>N/A</td>");
    lines.push(`<td>${escapeHtml(code)}</td>`);

    if (englishMatch?.same) {
      lines.push(`<td class="merged" colspan="2">${escapeHtml(cldrName)}</td>`);
    } else {
      const difference = nonAlphabeticDifference(wikidataEnglishName, cldrName) ||
        singleCharacterDifference(wikidataEnglishName, cldrName);
      const wikidataClass = difference
        ? ' class="near-match" title="English names differ slightly"'
        : englishMatch?.shorter === "wikidata" ? ' class="near-match" title="Shorter prefix/suffix match"' : "";
      const cldrClass = difference
        ? ' class="near-match" title="English names differ slightly"'
        : englishMatch?.shorter === "cldr" ? ' class="near-match" title="Shorter prefix/suffix match"' : "";
      lines.push(`<td${cldrClass}>${renderName(cldrName, difference?.cldr)}</td>`);
      lines.push(`<td${wikidataClass}>${renderName(wikidataEnglish, difference?.wikidata)}</td>`);
    }

    for (const cell of mergeableNames(zhNames, annotations, displayedMcaName)) {
      const merged = cell.colspan > 1 ? ' class="merged"' : "";
      const span = cell.colspan > 1 ? ` colspan="${cell.colspan}"` : "";
      const mcaMarkup = cell.mcaName ? `<br><small class="mca-label">${escapeHtml(cell.mcaName)}</small>` : "";
      lines.push(`<td${merged}${span}>${escapeHtml(cell.value)}${mcaMarkup}</td>`);
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
  const mcaNames = await loadMcaNames();
  const convert = Object.keys(mcaNames).length
    ? OpenCC.Converter({ from: "t", to: "cn" })
    : (value) => value;
  const { rows, skipped, added } = renderRows(csvRows);
  await fs.writeFile(output, renderHtml(rows, mcaNames, convert), "utf8");
  console.log(`Wrote ${rows.length} HTML rows to ${output}; added ${added} CLDR-only rows, skipped ${skipped} CSV rows without a CLDR code, and read ${Object.keys(mcaNames).length} MCA labels`);
}

module.exports = { loadMcaNames, mcaAnnotationIndices, normalizeForms, renderHtml, renderRows };

if (require.main === module) {
  main().catch((error) => {
    console.error(`HTML generation failed: ${error.message}`);
    process.exitCode = 1;
  });
}
