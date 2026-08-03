import express from 'express';
import { getPermissions, setPermissions, listPermissions } from '../services/core/permissions.js';
import { requireCapability } from '../services/security/require-capability.js';

const router = express.Router();

router.get('/', async (req, res, next) => {
  try {
    const agentId = req.query.agent_id;
    if (agentId) {
      const perms = await getPermissions(agentId, req.query.company_id);
      return res.json({ agent_id: agentId, permissions: perms });
    }
    const all = await listPermissions(req.query.company_id);
    return res.json({ permissions: all });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

// R1 Step 4: granting capabilities is the highest-value privilege-escalation
// target — without a gate, any admitted envelope could grant itself admin.
// Require admin_override from the signed append-only authorization ledger; only an admin
// may mutate the ledgered capability rows).
router.post('/set', requireCapability('admin_override'), async (req, res, next) => {
  const { agent_id, permissions } = req.body || {};
  if (!agent_id || !permissions) {
    return res.status(400).json({ success: false, error: 'agent_id and permissions are required' });
  }
  try {
    await setPermissions(
      agent_id,
      permissions,
      {
        kind: 'verified_request',
        body: req.body,
        agentId: req.executionContext?.actorAgentId || req.agentId,
        validFromIso: req.identityValidFromIso,
        certString: req.identityCertString,
        signedTs: req.identitySignedTs,
        nonce: req.identityNonce,
        sigBytes: req.identitySigBytes,
        identityTier: req.identityTier,
        requestSigForm: req.identityRequestSigForm,
        signedMethod: req.identitySignedMethod,
        signedPath: req.identitySignedPath,
        signedClaims: req.identitySignedClaims,
      },
      req.executionContext?.companyId
    );
    res.json({ success: true });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

export default router;
