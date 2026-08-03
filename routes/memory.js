import { AIMOS_COMPANY_ID } from '../services/core/runtime-config.js';
import express from 'express';
import { query } from '../db/connection.js';

const router = express.Router();

router.get('/stats', async (req, res, next) => {
  const company = req.query.company_id || AIMOS_COMPANY_ID;

  try {
    const [totalResult, byAgentResult, byTypeResult] = await Promise.all([
      query(
        `SELECT COUNT(*)::int AS total
         FROM aimos_memories
         WHERE company_id = $1`,
        [company]
      ),
      query(
        `SELECT agent_id, COUNT(*)::int AS count
         FROM aimos_memories
         WHERE company_id = $1
         GROUP BY agent_id
         ORDER BY count DESC`,
        [company]
      ),
      query(
        `SELECT memory_type AS type, COUNT(*)::int AS count
         FROM aimos_memories
         WHERE company_id = $1
         GROUP BY memory_type
         ORDER BY count DESC`,
        [company]
      )
    ]);

    res.json({
      total: totalResult.rows[0]?.total ?? 0,
      byAgent: byAgentResult.rows,
      byType: byTypeResult.rows
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

export default router;
