/**
 * agents.js — main agent router.
 *
 * Thin composition layer: imports and mounts the three bounded sub-routers.
 * All route logic lives in the sub-routers; this file owns only mount order.
 *
 * Mount order matters for Express prefix matching:
 *   1. agent-learning  — must be first because it registers /health/all and
 *      /messages/:key/read before the /:id wildcard can shadow them.
 *   2. agent-execution — registers /:id/run and /:id/stream.
 *   3. agent-management — registers /, /statuses, /sessions, /:id,
 *      /:id/status, and retained governance diagnostics.
 */

import express from 'express';
import managementRouter from './agent-management.js';
import executionRouter from './agent-execution.js';
import learningRouter from './agent-learning.js';

const router = express.Router();

// Learning routes first — /health/all and /messages/:key/read must not be
// captured by the /:id wildcard registered in management.
router.use('/', learningRouter);

// Execution routes — /:id/run and /:id/stream.
router.use('/', executionRouter);

// Management routes last — includes the catch-all /:id GET that would
// otherwise shadow more specific paths defined above.
router.use('/', managementRouter);

export default router;
