import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const ROOT = new URL('../../', import.meta.url);
const save = readFileSync(new URL('services/write/canonical-save-owner.js', ROOT), 'utf8');
const persistence = readFileSync(new URL('services/write/persist-memory.js', ROOT), 'utf8');

test('confirmed canonical credential commit owns cache publication and preserves inner standalone compatibility', () => {
  assert.match(save, /PUBLISHED_AFTER_COMMIT/);
  assert.match(save, /COMMITTED_PUBLICATION_UNAVAILABLE/);
  assert.match(save, /await deps\.refreshCachedCredential\(committed\.saved\.credential_service_name\)/);
  assert.match(save, /credential_cache_refresh_failed/);
  assert.match(save, /exclusiveOperationKey:true/);
  assert.match(persistence, /if \(ownsTransaction\) \{\s*try \{\s*await refreshCachedCredential/);
  assert.match(persistence, /credential_service_name: prepared\.service_name/);
  assert.doesNotMatch(save, /refreshCachedCredential\([^)]*\)[\s\S]{0,200}withTransaction/);
});

