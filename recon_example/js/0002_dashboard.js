// Fake dashboard JavaScript file for example recon output.
// This file exists only to make the sample output look realistic.

const adminRoutes = [
  "/api/v1/admin/users",
  "/api/v1/admin/roles",
  "/api/v1/admin/audit-log"
];

function loadAccountById() {
  const params = new URLSearchParams(window.location.search);
  const accountId = params.get("account_id");

  return fetch("/api/v1/accounts/" + accountId + "/settings");
}

function exportData() {
  window.location = "/api/v1/export/csv";
}

const webhookPath = "/webhooks/stripe/callback";

async function loadGraphQL() {
  return fetch("/internal/graphql", {
    method: "POST",
    body: JSON.stringify({
      query: "{ viewer { id email role } }"
    })
  });
}

const featureFlags = {
  adminMode: false,
  internalBillingExport: true,
  experimentalWebhookEditor: true
};
