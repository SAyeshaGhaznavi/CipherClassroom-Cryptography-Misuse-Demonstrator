import type { ExperimentInput, ExperimentResult, ExperimentType, Severity, TestResult } from './types';

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const hex = (bytes: Uint8Array): string => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const bytes = (buffer: ArrayBuffer): Uint8Array => new Uint8Array(buffer);
const bitDiff = (a: Uint8Array, b: Uint8Array): number => a.reduce((total, x, i) => {
  let xor = x ^ b[i]; let count = 0;
  while (xor) { xor &= xor - 1; count++; }
  return total + count;
}, 0);
const digest = async (text: string) => bytes(await crypto.subtle.digest('SHA-256', encoder.encode(text)));
const caesar = (text: string, shift: number) => text.replace(/[A-Za-z]/g, char => {
  const base = char >= 'a' ? 97 : 65;
  return String.fromCharCode(base + ((char.charCodeAt(0) - base + shift) % 26 + 26) % 26);
});
const safeText = (text: string) => {
  if (text.length === 0) throw new Error('Enter input text first.');
  if (text.length > 2000) throw new Error('Input must be 2,000 characters or fewer.');
  return text;
};
const make = (type: ExperimentType, title: string, severity: Severity, summary: string, details: ExperimentResult['details'], warnings: string[], evidence: ExperimentResult['evidence'], durationMs: number): ExperimentResult => ({
  id: crypto.randomUUID(), type, title, timestamp: new Date().toISOString(), status: 'completed', severity, summary,
  details, warnings, evidence, durationMs, version: 'frontend-demo-1.0'
});
const encryptGCM = async (plain: string, key: CryptoKey, iv: Uint8Array) => bytes(await crypto.subtle.encrypt({name:'AES-GCM', iv: iv as BufferSource},key,encoder.encode(plain)));
const getAESKey = () => crypto.subtle.generateKey({name:'AES-GCM', length:256},true,['encrypt','decrypt']);
const generateIv = () => crypto.getRandomValues(new Uint8Array(12));

export async function runDemo(input: ExperimentInput): Promise<ExperimentResult> {
  const start = performance.now();
  const text = safeText(input.text);
  const duration = () => Math.round((performance.now() - start) * 100) / 100;
  switch(input.type) {
    case 'classical-cipher': {
      const shift = input.shift ?? 3;
      if (!Number.isInteger(shift) || shift < 0 || shift > 25) throw new Error('Shift must be an integer between 0 and 25.');
      const ciphertext = caesar(text, shift);
      return make(input.type, 'Classical cipher', 'warning', 'Caesar cipher applied. This substitution cipher is not secure for modern use.',
        [{label:'Ciphertext',value:ciphertext},{label:'Decrypted (verification)',value:caesar(ciphertext,26-shift)},{label:'Shift',value:String(shift)}],
        ['Caesar cipher provides no modern confidentiality; it is easily reversed.'],[{name:'Method',value:'Alphabetic rotation (Caesar)'},{name:'Validation',value:'Shift restricted to 0–25'}],duration());
    }
    case 'authenticated-encryption': {
      const key = await getAESKey(); const iv = generateIv();
      const encrypted = await encryptGCM(text,key,iv);
      const decrypted = decoder.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:iv as BufferSource},key,encrypted as BufferSource));
      const altered = encrypted.slice(); altered[0] ^= 1;
      let tamperingRejected = false;
      try { await crypto.subtle.decrypt({name:'AES-GCM',iv:iv as BufferSource},key,altered as BufferSource); }
      catch { tamperingRejected = true; }
      return make(input.type,'Authenticated encryption','info','AES-256-GCM decrypted the original message and rejected the tampered ciphertext.',
        [{label:'Ciphertext + authentication tag (hex)',value:hex(encrypted)},{label:'Round-trip plaintext',value:decrypted},{label:'Tampering test',value:tamperingRejected?'PASS — modified data rejected':'FAIL — review required'}],
        [],[{name:'Algorithm',value:'AES-256-GCM'},{name:'Nonce size',value:'96 bits, randomly generated per run'},{name:'Integrity check',value:tamperingRejected?'Rejected modified ciphertext':'Unexpected'}],duration());
    }
    case 'hashing-kdfs': {
      const hash = await digest(text);
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iterations = input.iterations ?? 100000;
      if(!Number.isInteger(iterations) || iterations < 1000 || iterations > 300000) throw new Error('Iterations must be between 1,000 and 300,000.');
      const material = await crypto.subtle.importKey('raw',encoder.encode(text),'PBKDF2',false,['deriveBits']);
      const derived = bytes(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:salt as BufferSource,iterations},material,256));
      return make(input.type,'Hashing & KDFs',iterations < 100000?'warning':'info','SHA-256 produces a deterministic digest; PBKDF2 derives a salted key using configurable work.',
        [{label:'SHA-256 digest',value:hex(hash)},{label:'PBKDF2 output (demo only)',value:hex(derived)},{label:'Salt (hex)',value:hex(salt)},{label:'Iterations',value:String(iterations)}],
        iterations < 100000?['Lower work factors take less time; do not use these demo values as password-storage recommendations.']:[],
        [{name:'Algorithms',value:'SHA-256 and PBKDF2-HMAC-SHA-256'},{name:'KDF salt',value:'Random 128-bit salt'}],duration());
    }
    case 'nonce-reuse': {
      const second = safeText(input.secondary ?? '');
      const firstBytes = encoder.encode(text), secondBytes = encoder.encode(second);
      if(firstBytes.length !== secondBytes.length) throw new Error('For this demonstration, both messages must have the same UTF-8 byte length.');
      const key = await getAESKey(); const nonce = generateIv();
      const c1 = await encryptGCM(text,key,nonce); const c2 = await encryptGCM(second,key,nonce);
      const xorCipher = c1.slice(0,firstBytes.length).map((value,i)=>value^c2[i]);
      const xorPlain = firstBytes.map((value,i)=>value^secondBytes[i]);
      const matches = hex(xorCipher)===hex(xorPlain);
      return make(input.type,'Nonce reuse demonstration','critical','Reusing one AES-GCM nonce under the same key leaks a relationship between equal-length plaintexts.',
        [{label:'Ciphertext XOR (without tags)',value:hex(xorCipher)},{label:'Plaintext XOR',value:hex(xorPlain)},{label:'Relationship verified',value:matches?'YES — values match':'NO — unexpected'}],
        ['Never reuse a nonce with the same AES-GCM key. This isolated lesson intentionally demonstrates an unsafe construction.'],
        [{name:'Scope',value:'In-memory demonstration with generated key and nonce'},{name:'Observed relationship',value:'C1 XOR C2 = P1 XOR P2 (ciphertext portion)'}],duration());
    }
    case 'test-vectors': {
      const tests = await runTestVectors();
      const passed = tests.filter(t=>t.passed).length;
      return make(input.type,'Test-vector checker',passed===tests.length?'info':'critical',`${passed} of ${tests.length} reproducible checks passed.`,
        tests.map(t=>({label:`${t.passed?'PASS':'FAIL'} — ${t.name}`,value:`Expected: ${t.expected} | Actual: ${t.actual}`})),
        passed===tests.length?[]:['One or more test vectors failed.'],[{name:'Source',value:'Published SHA-256 test vectors and deterministic Caesar example'},{name:'Tests run',value:String(tests.length)}],duration());
    }
    case 'avalanche': {
      const original = encoder.encode(text);
      const modified = original.slice(); modified[0] ^= 1;
      const first = bytes(await crypto.subtle.digest('SHA-256',original));
      const second = bytes(await crypto.subtle.digest('SHA-256',modified));
      const changed = bitDiff(first,second);
      return make(input.type,'Avalanche measurement','info',`${changed} of 256 SHA-256 output bits changed after flipping one input bit.`,
        [{label:'Original SHA-256',value:hex(first)},{label:'Changed-input SHA-256',value:hex(second)},{label:'Changed output bits',value:`${changed} / 256 (${(changed/256*100).toFixed(2)}%)`}],
        [],[{name:'Input mutation',value:'First input byte XOR 0x01'},{name:'Measurement',value:'Hamming distance between digests'}],duration());
    }
  }
}
export async function runTestVectors(): Promise<TestResult[]> {
  const shaEmpty = hex(await digest(''));
  const shaABC = hex(await digest('abc'));
  return [
    {name:'SHA-256 empty string',expected:'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',actual:shaEmpty,passed:shaEmpty==='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
    {name:'SHA-256 abc',expected:'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',actual:shaABC,passed:shaABC==='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'},
    {name:'Caesar HELLO +3',expected:'KHOOR',actual:caesar('HELLO',3),passed:caesar('HELLO',3)==='KHOOR'}
  ];
}
