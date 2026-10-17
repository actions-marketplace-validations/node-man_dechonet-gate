#!/usr/bin/env node
// DechoNet gate — workflow supply-chain check (2026-10-17). Reads the repository's own .github/workflows on the
// runner — nothing is sent anywhere — and reports the patterns behind this year's GitHub Actions compromises:
//   high    pull_request_target that checks out the pull request's code ("pwn request")
//   high    untrusted event text (titles, bodies, branch names, commit messages) put into a run: script
//   medium  a third-party action not pinned to a full commit SHA (tags can be moved to malicious code)
//   medium  a secret printed with echo/printf
//   info    no top-level permissions: block (the token gets the repository default, often write)
// Line-based on purpose (no YAML library, no dependencies): it can miss unusual layouts, never runs anything.

import fs from 'node:fs';
import path from 'node:path';

const UNTRUSTED = /\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|review_comment|discussion|discussion_comment)\.(title|body|head\.ref|head\.label)|github\.head_ref|github\.event\.(head_commit\.message|head_commit\.author\.(name|email)|commits(\[\d+\]|\.\*)\.(message|author\.(name|email)))|github\.event\.pages(\[\d+\]|\.\*)\.page_name|github\.event\.workflow_run\.(head_branch|head_commit\.message))\s*\}\}/;
const PR_HEAD_REF = /\$\{\{\s*(github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref)\s*\}\}|refs\/pull\/\$\{\{/;
const FIRST_PARTY = /^(actions|github)\//i;

const indentOf = (line) => line.match(/^\s*/)[0].length;

/** Pure: findings for one workflow file. */
export function scanWorkflow(text, file = 'workflow.yml') {
  const lines = text.split(/\r?\n/);
  const out = [];
  const add = (severity, rule, line, message) => out.push({ severity, rule, file, line, message });
  const prTarget = /^\s*pull_request_target\s*:|^on\s*:.*\bpull_request_target\b|^\s*-\s*pull_request_target\s*$/m.test(text);
  let run = null; // { indent } while inside a run: block
  let inCheckout = null; // indent of the step that uses actions/checkout
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const ind = indentOf(line);
    if (run && ind <= run.indent) run = null;
    if (inCheckout !== null && ind <= inCheckout && /^\s*-\s/.test(line)) inCheckout = null;

    const runKey = /^(\s*)(-\s*)?run\s*:\s*(.*)$/.exec(line);
    if (runKey) {
      const inline = runKey[3];
      if (UNTRUSTED.test(inline)) add('high', 'script-injection', i + 1, `Untrusted event text in a run: script (${inline.match(UNTRUSTED)[0]}). Pass it through env: and quote it ("$TITLE").`);
      if (/^\s*(echo|printf)\b.*\$\{\{\s*secrets\./.test(inline)) add('medium', 'secret-echo', i + 1, 'A secret is printed. Do not echo secrets: masking misses transformed values.');
      if (/^[|>][-+]?\s*$/.test(inline) || inline === '') run = { indent: indentOf(line) + (runKey[2] ? 2 : 0) };
      continue;
    }
    if (run) {
      if (UNTRUSTED.test(line)) add('high', 'script-injection', i + 1, `Untrusted event text in a run: script (${line.match(UNTRUSTED)[0]}). Pass it through env: and quote it ("$TITLE").`);
      if (/^\s*(echo|printf)\b.*\$\{\{\s*secrets\./.test(line)) add('medium', 'secret-echo', i + 1, 'A secret is printed. Do not echo secrets: masking misses transformed values.');
      continue;
    }

    const uses = /^\s*(-\s*)?uses\s*:\s*["']?([^\s"'#]+)/.exec(line);
    if (uses) {
      const ref = uses[2];
      if (/^actions\/checkout@/i.test(ref)) inCheckout = indentOf(line) - (uses[1] ? 0 : 2);
      if (ref.startsWith('./') || ref.startsWith('docker://')) continue;
      const [repo, version = ''] = ref.split('@');
      if (!/^[0-9a-f]{40}$/i.test(version) && !FIRST_PARTY.test(repo)) add('medium', 'unpinned-action', i + 1, `${repo} is used by ${version ? `tag or branch "${version}"` : 'no version'} — pin it to a full commit SHA (a tag can be moved to other code).`);
      continue;
    }
    if (prTarget && inCheckout !== null && /^\s*ref\s*:/.test(line) && PR_HEAD_REF.test(line)) {
      add('high', 'pwn-request', i + 1, 'pull_request_target checks out the pull request\'s code with this repository\'s token and secrets. Use pull_request, or never run the checked-out code.');
    }
  }
  if (!/^permissions\s*:/m.test(text)) add('info', 'no-permissions', 1, 'No top-level permissions: — the token gets the repository default (often read and write). Set permissions: contents: read and widen per job.');
  return out;
}

const RANK = { info: 0, medium: 1, high: 2 };

/** Every .yml/.yaml under the directory. */
export function scanDir(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((f) => /\.ya?ml$/i.test(f)).flatMap((f) => scanWorkflow(fs.readFileSync(path.join(dir, f), 'utf8'), path.join(dir, f)));
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  const dir = process.env.DN_WORKFLOWS_DIR || '.github/workflows';
  const failOn = (process.env.DN_WORKFLOWS_FAIL_ON || 'high').toLowerCase();
  const findings = scanDir(dir);
  const summary = process.env.GITHUB_STEP_SUMMARY;
  const rows = findings.map((f) => `| ${f.severity} | ${f.rule} | ${f.file}:${f.line} | ${f.message.replace(/\|/g, '\\|')} |`);
  const md = ['### DechoNet workflow check', '', findings.length ? '| Severity | Rule | Where | What to do |' : 'No findings in ' + dir + '.', ...(findings.length ? ['|---|---|---|---|', ...rows] : []), '', 'Checked on the runner — workflow files are not sent anywhere.', ''].join('\n');
  if (summary) fs.appendFileSync(summary, md); else process.stdout.write(md + '\n');
  for (const f of findings) {
    const kind = f.severity === 'high' ? 'error' : f.severity === 'medium' ? 'warning' : 'notice';
    console.log(`::${kind} file=${f.file},line=${f.line},title=DechoNet ${f.rule}::${f.message}`);
  }
  const fail = failOn !== 'none' && findings.some((f) => RANK[f.severity] >= (RANK[failOn] ?? 2));
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `workflows-pass=${fail ? 'false' : 'true'}\n`);
  process.exit(fail ? 1 : 0);
}
