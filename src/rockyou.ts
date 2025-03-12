import * as fs from "fs";
import * as readline from "readline";
import * as crypto from "crypto";

//  The value of the target hash
const targetHash =
  "$2b$10$dTb0tY4yCaff9mzFg2ZUFuHpFVXkzIQJXCIPNqi6ramt..kZlKPCG";

// path rockyou.txt
const passwordFile = "../rockyou.txt";

// Calculate sha256
function sha256(password: string): string {
  return crypto.createHash("sha256").update(password).digest("hex");
}

// compare hash to the rockyou text
async function findMatchingPassword() {
  const fileStream = fs.createReadStream(passwordFile);
  const rl = readline.createInterface({
    input: fileStream,
    crlfDelay: Infinity,
  });

  for await (const password of rl) {
    const trimmedPassword = password.trim();
    const hashedPassword = sha256(trimmedPassword);

    if (hashedPassword === targetHash) {
      console.log(`[+] Found a password: ${trimmedPassword}`);
      return trimmedPassword;
    }
  }

  console.log("[-] Can not find a password.");
  return null;
}

// Execute
findMatchingPassword();
