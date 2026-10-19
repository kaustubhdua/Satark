import { readFile } from 'node:fs/promises';
import { evaluateLocalAnalysis } from '../src/lib/local-analysis-evaluation.mjs';

const corpus = JSON.parse(await readFile(new URL('../evaluation/local-analysis-cases.json', import.meta.url), 'utf8'));
const report = evaluateLocalAnalysis(corpus.cases);
process.stdout.write(JSON.stringify(report, null, 2) + '\n');
