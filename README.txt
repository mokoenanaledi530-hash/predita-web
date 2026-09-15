PREDITA WEB DASHBOARD — TERMUX QUICK START

1. Install Python:
   pkg update
   pkg install python

2. Install Flask:
   python -m pip install -r requirements.txt

3. Set a local admin password and secret:
   export PREDITA_ADMIN_USER=admin
   export PREDITA_ADMIN_PASSWORD='CHANGE-THIS-PASSWORD'
   export PREDITA_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"

4. Start:
   python predita_web.py

5. Open on the same device:
   http://127.0.0.1:5000

Optional LAN testing only:
   export PREDITA_HOST=0.0.0.0
   python predita_web.py

FILES / DATA
- Default SQLite DB: predita_cases.db
- Default evidence folder: evidence_uploads/
- Maximum upload: 10 MB
- Supported import format: CSV
- Datasets: calls, SMS metadata, subscriber/RICA exports
- Duplicate evidence is detected by SHA-256 per case/dataset.

IMPORTANT
This is a development dashboard. It does not fetch private carrier/government records.
It only imports records already lawfully obtained and supplied to the case.
Before production use, replace the local environment-password login with agency SSO/MFA,
use managed encrypted storage, TLS, centralized audit logging, least-privilege roles,
retention/deletion controls, backups, and a documented evidence-handling process.


MTN PROVIDER CHECK (OPTIONAL, DISABLED BY DEFAULT)
-------------------------------------------------
Predita includes a server-side adapter for the official MTN Mobile Customer
Information SIM-swap-date operation.

Do not enable it until MTN has approved your application and issued credentials.

Example with an API key:
  export PREDITA_ENABLE_MTN_CHECKS=1
  export MTN_API_KEY='YOUR_APPROVED_KEY'

Or, if your approved MTN flow issues an OAuth bearer token:
  export PREDITA_ENABLE_MTN_CHECKS=1
  export MTN_BEARER_TOKEN='YOUR_SHORT_LIVED_TOKEN'

Then restart:
  python predita_web.py

Do not place provider credentials in HTML, JavaScript, CSV files, source control,
screenshots, or chat. Keep them in server environment variables / a secret manager.

Vodafone/Vodacom:
The dashboard does not treat Number Verify as an investigator phone lookup. Vodafone
documents it as customer/device verification with an OAuth authorization flow. Call
data records and RICA/ownership records should continue through the authorized LEA/
records process and enter Predita as controlled evidence.


EVIDENCE RECEIPT WORKFLOW (v3)
------------------------------
1. Open a case.
2. Use "Receive authorized evidence".
3. Choose calls, SMS metadata, or subscriber/RICA records.
4. Record the provider/source, authority reference and provider/transfer reference.
5. Upload the original CSV.
6. Predita stores the original file unchanged and calculates SHA-256.
7. A separate "Verify hash + import" action recomputes SHA-256 before parsing.
8. Only successfully verified/imported records become searchable.
9. Rejected evidence remains preserved locally and is marked rejected; it is not imported.

For production:
- Put evidence storage on encrypted, access-controlled managed storage.
- Do not use a shared consumer Downloads folder as evidence storage.
- Define retention/deletion rules with the agency.
- Replace local admin login with agency SSO/MFA and role separation.
- Consider making evidence-approval a different role from evidence receipt.


ROLE-BASED ACCESS (v4)
----------------------
Roles:
- intake: create cases, validate ID structure, receive/hash evidence
- investigator: create/view cases, validate IDs, search imported records, run enabled provider checks
- approver: view/search cases, verify hashes, approve/reject evidence imports
- admin: all application permissions plus user creation

By default, the person who receives evidence CANNOT approve/import that same receipt.
For local throwaway testing only, this can be bypassed with:
  export PREDITA_ALLOW_SELF_APPROVAL=1
Do not enable that in a real deployment.

First start / bootstrap:
  export PREDITA_ADMIN_USER=admin
  export PREDITA_ADMIN_PASSWORD='A-STRONG-BOOTSTRAP-PASSWORD'
  export PREDITA_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
  python predita_web.py

The first start creates the local admin in the database using a password hash.
After that, use the Users page to create separate intake, investigator, and approver accounts.

Session controls:
  export PREDITA_SESSION_MINUTES=30
  export PREDITA_HTTPS_ONLY=0   # local HTTP only
For TLS production behind a reverse proxy:
  export PREDITA_HTTPS_ONLY=1

Production server example:
  gunicorn -c gunicorn.conf.py predita_web:app

IMPORTANT:
- Gunicorn is a production WSGI server, but this package is still a prototype until the
  agency chooses the hosting platform, TLS/reverse proxy, managed database, encrypted
  evidence storage, backups, centralized logs, SSO/MFA, retention rules, and security review.
- Local password accounts are a transition mechanism, not a claim of Hawks/SAPS SSO integration.
