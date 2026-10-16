# Wikidata subdivision labels

This pipeline queries Wikidata subdivision labels and renders the results against the English subdivision names in `cldr-subdivisions-full` 48.2.0.

## Run locally

```sh
npm ci
npm run query
npm run render
```

`query_wikidata.js` writes `wikiSubdivisionLanguages.csv` for AU, DE, ES, FR, GB, GR, IT, JP, KR, MY, MX, TH, TR, US, and VN, with `en`, `zh-cn`, `zh`, and `zh-tw` labels. `render_html.js` filters codes to the package’s English subdivision data and writes `wikiSubdivisionLanguages.html`. Different Wikidata items with the same subdivision code remain separate rows. It shows `N/A` for missing labels, merges identical names, and lightly highlights the shorter English name when it is a whole-string prefix or suffix of the other.
