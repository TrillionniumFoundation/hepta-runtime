export function twice(input) {
  const text = "🔥";
  return input * 2 + text.length;
}
const branch = flag => flag ? twice(3) : 0;