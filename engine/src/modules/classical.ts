/**
 * FR-2 Classical cipher module.
 *
 * Caesar and Vigenere, plus a frequency attack that recovers a Caesar shift
 * with no knowledge of the key. The attack is the teaching point: it is the
 * measurable evidence that these ciphers provide no confidentiality.
 */

/** Relative frequency of each letter in ordinary English text, A through Z. */
const ENGLISH_FREQUENCIES: number[] = [
  8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153,
  0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056,
  2.758, 0.978, 2.36, 0.15, 1.974, 0.074
];

const UPPER_A = 65;
const LOWER_A = 97;

function isUpperLetter(code: number): boolean {
  return code >= 65 && code <= 90;
}

function isLowerLetter(code: number): boolean {
  return code >= 97 && code <= 122;
}

/** Shifts every letter by the given amount, leaving other characters alone. */
export function caesarEncrypt(text: string, shift: number): string {
  let out = '';
  const normalizedShift = ((shift % 26) + 26) % 26;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (isUpperLetter(code)) {
      const position = code - UPPER_A;
      const shifted = (position + normalizedShift) % 26;
      out = out + String.fromCharCode(UPPER_A + shifted);
    } else if (isLowerLetter(code)) {
      const position = code - LOWER_A;
      const shifted = (position + normalizedShift) % 26;
      out = out + String.fromCharCode(LOWER_A + shifted);
    } else {
      out = out + text[i];
    }
  }
  return out;
}

export function caesarDecrypt(text: string, shift: number): string {
  const normalizedShift = ((shift % 26) + 26) % 26;
  return caesarEncrypt(text, 26 - normalizedShift);
}

/** Vigenere encryption. The keyword must already be validated letters A to Z. */
export function vigenereEncrypt(text: string, keyword: string): string {
  let out = '';
  let keyPosition = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    const keyShift = keyword.charCodeAt(keyPosition % keyword.length) - UPPER_A;
    if (isUpperLetter(code)) {
      const shifted = (code - UPPER_A + keyShift) % 26;
      out = out + String.fromCharCode(UPPER_A + shifted);
      keyPosition = keyPosition + 1;
    } else if (isLowerLetter(code)) {
      const shifted = (code - LOWER_A + keyShift) % 26;
      out = out + String.fromCharCode(LOWER_A + shifted);
      keyPosition = keyPosition + 1;
    } else {
      out = out + text[i];
    }
  }
  return out;
}

export function vigenereDecrypt(text: string, keyword: string): string {
  let inverted = '';
  for (let i = 0; i < keyword.length; i++) {
    const keyShift = keyword.charCodeAt(i) - UPPER_A;
    const invertedShift = (26 - keyShift) % 26;
    inverted = inverted + String.fromCharCode(UPPER_A + invertedShift);
  }
  return vigenereEncrypt(text, inverted);
}

export interface ShiftScore {
  shift: number;
  /** Chi squared statistic. Lower means a closer match to English. */
  score: number;
}

export interface FrequencyBreakResult {
  recoveredShift: number;
  recoveredPlaintext: string;
  rankedShifts: ShiftScore[];
  letterCounts: number[];
  totalLetters: number;
}

/** Counts A to Z in the text, case insensitive. */
export function countLetters(text: string): number[] {
  const counts: number[] = [];
  for (let i = 0; i < 26; i++) {
    counts.push(0);
  }
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (isUpperLetter(code)) {
      counts[code - UPPER_A] = counts[code - UPPER_A] + 1;
    } else if (isLowerLetter(code)) {
      counts[code - LOWER_A] = counts[code - LOWER_A] + 1;
    }
  }
  return counts;
}

/**
 * Recovers a Caesar shift without the key.
 *
 * For each of the 26 candidate shifts the text is undone and the resulting
 * letter distribution is compared against English with a chi squared
 * statistic. The candidate with the lowest statistic is the answer.
 */
export function frequencyBreak(ciphertext: string): FrequencyBreakResult {
  const counts = countLetters(ciphertext);
  let totalLetters = 0;
  for (let i = 0; i < counts.length; i++) {
    totalLetters = totalLetters + counts[i];
  }

  const ranked: ShiftScore[] = [];
  for (let shift = 0; shift < 26; shift++) {
    let score = 0;
    for (let letter = 0; letter < 26; letter++) {
      // Undoing `shift` moves the count at (letter + shift) onto `letter`.
      const sourceIndex = (letter + shift) % 26;
      const observed = counts[sourceIndex];
      let expected = 0;
      if (totalLetters > 0) {
        expected = (ENGLISH_FREQUENCIES[letter] / 100) * totalLetters;
      }
      if (expected > 0) {
        const difference = observed - expected;
        score = score + (difference * difference) / expected;
      }
    }
    ranked.push({ shift: shift, score: Math.round(score * 1000) / 1000 });
  }

  // Selection sort by score, ascending. Explicit so the ranking is auditable.
  for (let i = 0; i < ranked.length; i++) {
    let smallest = i;
    for (let j = i + 1; j < ranked.length; j++) {
      if (ranked[j].score < ranked[smallest].score) {
        smallest = j;
      }
    }
    if (smallest !== i) {
      const temporary = ranked[i];
      ranked[i] = ranked[smallest];
      ranked[smallest] = temporary;
    }
  }

  const bestShift = ranked[0].shift;
  return {
    recoveredShift: bestShift,
    recoveredPlaintext: caesarDecrypt(ciphertext, bestShift),
    rankedShifts: ranked,
    letterCounts: counts,
    totalLetters: totalLetters
  };
}

/** Index of coincidence. Around 0.067 for English, around 0.038 for random text. */
export function indexOfCoincidence(text: string): number {
  const counts = countLetters(text);
  let total = 0;
  for (let i = 0; i < counts.length; i++) {
    total = total + counts[i];
  }
  if (total < 2) {
    return 0;
  }
  let sum = 0;
  for (let i = 0; i < counts.length; i++) {
    sum = sum + counts[i] * (counts[i] - 1);
  }
  const value = sum / (total * (total - 1));
  return Math.round(value * 10000) / 10000;
}
