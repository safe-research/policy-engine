/**
 * Verifies that the vendored `safe-research/safenet` sources still match upstream.
 *
 * Each vendored file records the commit it came from in its own header. This script re-downloads
 * that exact commit, replays the documented transformation, and diffs the result against what is on
 * disk. It therefore catches both directions of drift: a local edit that was never sent upstream,
 * and a header that claims a commit its contents do not correspond to.
 *
 * Run with `npm run vendor:check`. Requires network access to raw.githubusercontent.com.
 */
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'

const RAW_BASE = 'https://raw.githubusercontent.com/safe-research/safenet'

/**
 * How a vendored file is compared against upstream.
 *
 * - `full`: the local file is reproducible from upstream by replaying the transformation, so every
 *   byte is compared, doc comments included.
 * - `code`: only the declaration onwards is compared. Used where the leading comment block was
 *   deliberately rewritten for this package and cannot be reconstructed.
 */
type Comparison = 'full' | 'code'

type Vendored = {
  local: string
  upstream: string
  comparison: Comparison
}

const VENDORED: Vendored[] = [
  { local: 'contracts/libraries/Secp256k1.sol', upstream: 'Secp256k1.sol', comparison: 'full' },
  { local: 'contracts/libraries/FROST.sol', upstream: 'FROST.sol', comparison: 'full' },
  { local: 'contracts/libraries/ConsensusMessages.sol', upstream: 'ConsensusMessages.sol', comparison: 'full' },
  { local: 'contracts/libraries/EpochRollover.sol', upstream: 'EpochRollover.sol', comparison: 'full' },
  // The vendoring note in this one's NatSpec was rewritten by hand, so only the library body is
  // reproducible from upstream.
  {
    local: 'contracts/libraries/SignatureExtension.sol',
    upstream: 'SignatureExtension.sol',
    comparison: 'code'
  }
]

/** Extracts the 40-hex upstream commit a vendored file claims to come from. */
function commitOf(source: string, local: string): string {
  const match = source.match(/\b([0-9a-f]{40})\b/)
  if (!match) {
    throw new Error(`${local}: no upstream commit found in the vendoring header`)
  }
  return match[1]
}

/**
 * Replays the transformation applied when vendoring: the licence header is relabelled to this
 * package's, and the Foundry `@/libraries/` remapping is rewritten to a relative path.
 */
function transform(upstream: string): string {
  return upstream
    .replace('// SPDX-License-Identifier: GPL-3.0-only\n', '// SPDX-License-Identifier: LGPL-3.0-only\n')
    .replace(/from "@\/libraries\//g, 'from "./')
}

/** Drops everything before the top-level declaration, leaving the body to compare. */
function codeOnly(source: string): string {
  const match = source.match(/^(library|contract|interface|abstract contract) /m)
  if (!match || match.index === undefined) {
    throw new Error('no top-level declaration found')
  }
  return source.slice(match.index)
}

/**
 * Removes the provenance block this repo inserts after the pragma, so the remainder lines up with
 * upstream. The block is the run of `//` comments introduced by the "Vendored from" line.
 */
function stripProvenance(local: string): string {
  const lines = local.split('\n')
  const start = lines.findIndex((line) => line.startsWith('// Vendored from'))
  if (start === -1) {
    return local
  }
  let end = start
  while (end < lines.length && lines[end].startsWith('//')) {
    end++
  }
  // The inserted block is preceded by a blank line that was not in upstream.
  const from = start > 0 && lines[start - 1] === '' ? start - 1 : start
  lines.splice(from, end - from)
  return lines.join('\n')
}

function digest(value: string): string {
  return createHash('sha256').update(value).digest('hex').slice(0, 12)
}

async function fetchUpstream(commit: string, upstream: string): Promise<string> {
  const url = `${RAW_BASE}/${commit}/contracts/src/libraries/${upstream}`
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`${url}: HTTP ${response.status}`)
  }
  return await response.text()
}

async function main(): Promise<void> {
  const failures: string[] = []

  for (const { local, upstream, comparison } of VENDORED) {
    const onDisk = await readFile(join(process.cwd(), local), 'utf-8')
    const commit = commitOf(onDisk, local)
    const fromUpstream = transform(await fetchUpstream(commit, upstream))

    const [actual, expected] =
      comparison === 'full' ? [stripProvenance(onDisk), fromUpstream] : [codeOnly(onDisk), codeOnly(fromUpstream)]

    if (actual === expected) {
      console.log(`  ok  ${local}  (${commit.slice(0, 10)}, ${comparison})`)
    } else {
      failures.push(local)
      console.log(`FAIL  ${local}  (${commit.slice(0, 10)}, ${comparison})`)
      console.log(`      local ${digest(actual)} != upstream ${digest(expected)}`)
    }
  }

  if (failures.length > 0) {
    console.error(
      `\n${failures.length} vendored file(s) diverge from upstream. Either re-vendor from the ` +
        `recorded commit, or update the commit in the file header if the change was intentional.`
    )
    process.exit(1)
  }

  console.log(`\nAll ${VENDORED.length} vendored files match upstream.`)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
