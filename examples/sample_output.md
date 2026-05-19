## Example Output

Interesting endpoints:
- /api/v1/users/me
- /api/v1/billing/invoices
- /internal/graphql

Potential next manual checks:
- IDOR on user/account endpoints
- Authz checks on billing routes
- GraphQL introspection / sensitive queries
