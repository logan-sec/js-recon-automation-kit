// Fake sample JavaScript file for JS Recon Automation Kit example output.
// These endpoints and keys are fake. Do not use for real testing.

const API_BASE = "/api/v1";

async function loadCurrentUser() {
  return fetch("/api/v1/users/me");
}

async function loadAccountSettings() {
  return fetch("/api/v1/account/settings");
}

function getUser(userId) {
  return fetch("/api/v1/users/" + userId);
}

function getInvoice(invoiceId) {
  return fetch("/api/v1/billing/invoices/" + invoiceId);
}

async function loadBilling() {
  return fetch("/api/v1/billing/invoices");
}

const routes = [
  "/internal/graphql",
  "/api/v1/export/csv",
  "/webhooks/stripe/callback",
  "/api/v1/admin/users"
];

const redirectUri = "https://example.com/oauth/callback";

const next = new URLSearchParams(location.search).get("redirect");

if (next) {
  window.location.href = next;
}

// Fake example values for SecretFinder-style output testing.
const googleApiKey = "AIzaSyD_FAKE_EXAMPLE_KEY_DO_NOT_USE_123456789";
const twilioAccountSid = "AC00000000000000000000000000000000";
const twilioAuthToken = "00000000000000000000000000000000";
const herokuApiKey = "FAKE-HEROKU-KEY-DO-NOT-USE-000000000000";
