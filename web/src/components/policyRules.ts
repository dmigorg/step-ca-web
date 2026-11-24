export function mergePolicyRules(rules: string[], input: string): string[] {
  const values = input.split(',').map(value => value.trim())
    .filter(value => value && !rules.includes(value))
  return [...rules, ...new Set(values)]
}
