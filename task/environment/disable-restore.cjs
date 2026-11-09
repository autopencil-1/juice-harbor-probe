/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

const fs = require('node:fs')

const file = process.argv[2] || '/juice-shop/build/server.js'
let source = fs.readFileSync(file, 'utf8')
const routes = [
  ['/rest/continue-code-findIt/apply/:continueCode', 'restoreProgressFindIt'],
  ['/rest/continue-code-fixIt/apply/:continueCode', 'restoreProgressFixIt'],
  ['/rest/continue-code/apply/:continueCode', 'restoreProgress']
]
const replacements = routes.map(([route, handler]) => {
  const original = `app.put('${route}', utils.asyncHandler(restoreProgress.${handler}()));`
  if (source.split(original).length !== 2) {
    throw new Error(`Expected exactly one progress restoration route: ${route}`)
  }
  return [original, `app.put('${route}', (_req, res) => res.status(403).json({ error: 'Progress restoration is disabled for this benchmark.' }));`]
})
for (const [original, replacement] of replacements) {
  source = source.replace(original, replacement)
}
fs.writeFileSync(file, source)
