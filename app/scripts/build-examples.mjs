// Regenerates examples/*.json from the company's Excel templates.
// Usage: node scripts/build-examples.mjs <industrial.xlsx> <consumer.xlsx>
import fs from 'node:fs';
import path from 'node:path';
import { importTemplateXlsx } from '../src/import/xlsx.js';

const out = path.join(import.meta.dirname, '..', 'examples');
const [industrial, consumer] = process.argv.slice(2);
if (!industrial || !consumer) { console.error('Usage: node scripts/build-examples.mjs <industrial.xlsx> <consumer.xlsx>'); process.exit(1); }
for (const [file, name, title] of [[industrial, 'industrial', 'Example – Wastewater pump controller (commercial)'], [consumer, 'consumer', 'Example – Smart pool controller (consumer)']]) {
  const { data } = await importTemplateXlsx(fs.readFileSync(file));
  data.meta.title = title;
  fs.writeFileSync(path.join(out, `${name}.json`), JSON.stringify(data, null, 1));
  console.log('wrote', name, data.risks.length, 'risks');
}
