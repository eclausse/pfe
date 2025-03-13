import crypto from "crypto";

// Target Hash value
const targetHash =
  "22a89f6f93412ecad98cec961cec37a2ca019d7205cd07812c358205ae3e4233";

const charset =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

// Setting the length of password
const minLength = 1;
const maxLength = 9;

// Generate all possibilities
function* generateCombinations(
  chars: string,
  length: number
): Generator<string> {
  if (length === 1) {
    for (let char of chars) {
      yield char;
    }
  } else {
    for (let char of chars) {
      for (let suffix of generateCombinations(chars, length - 1)) {
        yield char + suffix;
      }
    }
  }
}

// Calculate SHA-256 hash
function sha256(password: string): string {
  return crypto.createHash("sha256").update(password).digest("hex");
}

// Brute-force function
async function bruteForceSHA256() {
  for (let length = minLength; length <= maxLength; length++) {
    console.log(`[+] testing ${length} length password`);

    for (let password of generateCombinations(charset, length)) {
      const hashedPassword = sha256(password);

      if (hashedPassword === targetHash) {
        console.log(`[+] Found a password : ${password}`);
        return password;
      }
    }
  }
  console.log("[-] Can't find a password");
  return null;
}

// Execute
bruteForceSHA256();
