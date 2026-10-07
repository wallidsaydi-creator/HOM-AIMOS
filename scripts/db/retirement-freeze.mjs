// PostgreSQL-native admission barrier for retiring one old AIMOS database.
// ALTER DATABASE ... ALLOW_CONNECTIONS false blocks new sessions, but retains
// those already admitted. A keeper session remains open for the final
// repeatable-read fingerprint while pg_stat_activity must show no peer session.
// DROP runs only after the keeper closes and the session count reaches zero.

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function fail(reason) { throw new Error(`retirement_freeze_${reason}`); }

async function databaseRow(admin, name) {
  return (await admin.query(`SELECT oid::text AS oid, datname,
    pg_get_userbyid(datdba) AS owner, datallowconn
    FROM pg_database WHERE datname=$1`, [name])).rows[0] || null;
}

function assertDatabase(row, { name, oid, owner, allowConnections }) {
  if (!row || row.datname !== name || row.oid !== String(oid)
      || row.owner !== owner
      || (allowConnections !== undefined
        && row.datallowconn !== allowConnections)) {
    fail('database_identity_or_admission_changed');
  }
}

async function sessionsForDatabase(admin, oid) {
  return (await admin.query(`SELECT pid FROM pg_stat_activity
    WHERE datid=$1::oid ORDER BY pid`, [String(oid)])).rows;
}

export async function freezeVerifyAndDropDatabase({
  admin, name, oid, owner, openKeeper,
  readFingerprint, compareFingerprint,
  onFrozenVerified = async () => {},
  onReenabled = async () => {},
  settleMs = 100,
} = {}) {
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(String(name || ''))
      || !/^\d+$/.test(String(oid || ''))
      || !/^[a-z][a-z0-9_]{0,62}$/.test(String(owner || ''))
      || !admin || typeof openKeeper !== 'function'
      || typeof readFingerprint !== 'function'
      || typeof compareFingerprint !== 'function'
      || !Number.isInteger(settleMs) || settleMs < 0 || settleMs > 1000) {
    fail('inputs_invalid');
  }
  assertDatabase(await databaseRow(admin, name), {
    name, oid, owner, allowConnections: true,
  });
  let keeper;
  let attemptedFreeze = false;
  let fingerprint;
  try {
    keeper = await openKeeper();
    const keeperPid = Number((await keeper.query('SELECT pg_backend_pid() AS pid')).rows[0]?.pid);
    if (!Number.isInteger(keeperPid) || keeperPid < 1) fail('keeper_pid_invalid');
    attemptedFreeze = true;
    await admin.query(`ALTER DATABASE ${name} WITH ALLOW_CONNECTIONS false`);
    assertDatabase(await databaseRow(admin, name), {
      name, oid, owner, allowConnections: false,
    });
    await sleep(settleMs);
    const admitted = await sessionsForDatabase(admin, oid);
    if (admitted.length !== 1 || Number(admitted[0].pid) !== keeperPid) {
      fail('peer_session_present_after_freeze');
    }
    await keeper.query('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
    try {
      fingerprint = await readFingerprint(keeper);
      await keeper.query('COMMIT');
    } catch (error) {
      await keeper.query('ROLLBACK').catch(() => {});
      throw error;
    }
    await compareFingerprint(fingerprint);
    await keeper.end(); keeper = null;
    if ((await sessionsForDatabase(admin, oid)).length !== 0) {
      fail('session_present_before_drop');
    }
    await onFrozenVerified(fingerprint);
    await admin.query(`DROP DATABASE ${name}`);
    if (await databaseRow(admin, name)) fail('drop_postcondition_invalid');
    return Object.freeze({ dropped: true, frozen: true, fingerprint });
  } catch (error) {
    await keeper?.end().catch(() => {});
    if (attemptedFreeze) {
      try {
        const row = await databaseRow(admin, name);
        if (row) {
          assertDatabase(row, { name, oid, owner });
          if (row.datallowconn === false) {
            await admin.query(`ALTER DATABASE ${name} WITH ALLOW_CONNECTIONS true`);
          }
          assertDatabase(await databaseRow(admin, name), {
            name, oid, owner, allowConnections: true,
          });
          await onReenabled();
        }
      } catch (recoveryError) {
        throw new AggregateError([error, recoveryError],
          'retirement_freeze_and_reenable_failed');
      }
    }
    throw error;
  }
}

export async function reenableFrozenDatabase({ admin, name, oid, owner } = {}) {
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(String(name || ''))
      || !/^\d+$/.test(String(oid || ''))
      || !/^[a-z][a-z0-9_]{0,62}$/.test(String(owner || ''))
      || !admin) fail('inputs_invalid');
  const before = await databaseRow(admin, name);
  assertDatabase(before, { name, oid, owner });
  if (before.datallowconn === false) {
    await admin.query(`ALTER DATABASE ${name} WITH ALLOW_CONNECTIONS true`);
  }
  assertDatabase(await databaseRow(admin, name), {
    name, oid, owner, allowConnections: true,
  });
  return Object.freeze({ reenabled: true,
    changed: before.datallowconn === false });
}
