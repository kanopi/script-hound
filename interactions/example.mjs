// Example interaction hook. Reference it from sites.json:
//   "interactions": [{ "match": "/checkout", "script": "interactions/example.mjs" }]
// Paths are relative to sites.json. The scanner never submits forms: a guard answers any
// form POST with "204 No Content", so the page stays put even if a step clicks "Pay".
//
// Anything that loads while a step() runs is tagged with that step's label in the reports
// (e.g. "ON CUSTOM: OPEN PAYMENT").
export default async function ({ page, url, profile, step, log }) {
  log(`example hook on ${url} (${profile})`);

  await step('open payment section', async () => {
    await page.getByRole('button', { name: /pay with card|credit card/i }).first().click({ timeout: 5000 });
  });

  await step('type card in hosted field', async () => {
    const card = page.frameLocator('iframe[title*="card number" i]').locator('input').first();
    await card.pressSequentially('4111111111111111', { delay: 20, timeout: 5000 });
  });

  await step('let listeners react', () => page.waitForTimeout(1500));
}
