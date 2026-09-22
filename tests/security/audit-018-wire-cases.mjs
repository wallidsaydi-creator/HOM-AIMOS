// Exact-wire protocol vectors. Acceptance here is NOT typed action authority.
export const wireSchema = 'hom.aimos.event/v2';
export const wireCases = [
  ['ascii', '{"b":2,"a":1}', true],
  ['ascii_reordered', '{"a":1,"b":2}', true],
  ['utf16_utf8_key_order', '{"\ue000":1,"\u{10000}":2}', true],
  ['nested', '{"a":[{"\ue000":1,"\u{10000}":2}],"10":1,"2":2}', true],
  ['escapes', '{"text":"\\b\\t\\n\\f\\r\\\"\\\\/"}', true],
  ['unicode_values', '{"text":"é😀é"}', true],
  ['negative_zero', '-0', true], ['zero', '0', true],
  ['integral_float', '1.0', true], ['integral_exponent', '1e0', true],
  ['fraction_scale', '4.50', true], ['small_exponent', '1e-7', true],
  ['safe_edge', '9007199254740991', true],
  ['opaque_large_integer', '9007199254740992.0', true],
  ['opaque_large_exponent', '1e400', true],
  ['duplicate', '{"a":1,"a":2}', false],
  ['escaped_duplicate', '{"a":1,"\\u0061":2}', false],
  ['unicode_duplicate', '{"😀":1,"\\ud83d\\ude00":2}', false],
  ['sibling_names', '{"a":{"x":1},"b":{"x":2}}', true],
  ['nul_value', '{"x":"\\u0000"}', false],
  ['nul_key', '{"\\u0000":1}', false],
  ['lone_high', '{"x":"\\ud800"}', false],
  ['lone_low', '{"x":"\\udfff"}', false],
  ['nan', 'NaN', false], ['infinity', 'Infinity', false],
  ['trailing', '{"a":1}[]', false], ['incomplete', '{"a":', false],
  ['depth32', '['.repeat(32) + '0' + ']'.repeat(32), true],
  ['depth33', '['.repeat(33) + '0' + ']'.repeat(33), false],
].map(([name, text, accepted]) => ({ name, wire: Buffer.from(text), accepted }));
wireCases.push({ name: 'invalid_utf8', wire: Buffer.from([0xff]), accepted: false });
wireCases.push({ name: 'bom', wire: Buffer.from('\ufeff{}'), accepted: false });
