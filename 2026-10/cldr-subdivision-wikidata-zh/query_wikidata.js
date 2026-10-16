#!/usr/bin/env node
"use strict";

const fs = require("node:fs/promises");
const path = require("node:path");

const ENDPOINT = "https://query.wikidata.org/sparql";
const COUNTRIES = ["AU", "DE", "ES", "FR", "GB", "GR", "IT", "JP", "KR", "MY", "MX", "TH", "TR", "US", "VN"];
const LANGUAGES = ["en", "zh-cn", "zh", "zh-tw"];
const OUTPUT = path.join(__dirname, "wikiSubdivisionLanguages.csv");
const HEADERS = ["item", "label", "code", "codeLabel"];
const COUNTRY_REGEX = `^(${COUNTRIES.join("|")})-`;
const LANGUAGE_VALUES = LANGUAGES.map((language) => `"${language}"`).join(", ");
// Adapted from the upstream query; these filters select the configured countries and languages:
// https://github.com/unicode-org/cldr/blob/main/tools/cldr-rdf/src/main/resources/org/unicode/cldr/rdf/sparql/wikidata-wikisubdivisionLanguages.sparql
const QUERY = `
PREFIX wdt: <http://www.wikidata.org/prop/direct/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT ?item ?label ?code ?codeLabel
WHERE {
  ?item wdt:P300 ?code;
        rdfs:label ?label.
  BIND(LANG(?label) AS ?codeLabel)
  FILTER(REGEX(STR(?code), "${COUNTRY_REGEX}"))
  FILTER(?codeLabel IN (${LANGUAGE_VALUES}))
}
ORDER BY ?code ?codeLabel ?item
`;

function csvField(value) {
  const text = String(value ?? "");
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

async function queryWikidata() {
  const requestBody = new URLSearchParams({ query: QUERY });
  const timeout = Number(process.env.WIKIDATA_TIMEOUT_MS || 120000);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(ENDPOINT, {
      method: "POST",
      headers: {
        Accept: "application/sparql-results+json",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "User-Agent": "cldr-subdivision-wikidata-zh/1.0 (Node.js)",
      },
      body: requestBody,
      signal: controller.signal,
    });
    const body = await response.text();
    if (!response.ok) {
      throw new Error(`Wikidata returned HTTP ${response.status}: ${body.slice(0, 500)}`);
    }

    const bindings = JSON.parse(body).results.bindings;
    return bindings.map((binding) =>
      HEADERS.map((name) => binding[name]?.value ?? ""),
    );
  } finally {
    clearTimeout(timer);
  }
}

async function main() {
  const output = process.argv[2] ? path.resolve(process.argv[2]) : OUTPUT;
  let rows;
  let lastError;

  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      rows = await queryWikidata();
      break;
    } catch (error) {
      lastError = error;
      if (attempt === 3) break;
      const delay = attempt * 3000;
      console.error(`Wikidata request ${attempt} failed; retrying in ${delay / 1000}s: ${error.message}`);
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }

  if (!rows) throw lastError;
  const csv = [HEADERS, ...rows].map((row) => row.map(csvField).join(",")).join("\n") + "\n";
  await fs.writeFile(output, csv, "utf8");
  console.log(`Wrote ${rows.length} rows to ${output}`);
}

main().catch((error) => {
  console.error(`Wikidata query failed: ${error.message}`);
  process.exitCode = 1;
});
