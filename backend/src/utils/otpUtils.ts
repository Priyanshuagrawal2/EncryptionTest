export function generateOTP(): string {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

export function verifyOTP(inputOTP: string, storedOTP: string): boolean {
  return inputOTP === storedOTP;
}
