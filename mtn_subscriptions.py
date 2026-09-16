import json
import os
import re
import time
from urllib.parse import quote

import requests
from flask import flash, request, session

_TOKEN_CACHE = {"access_token": None, "expires_at": 0.0}


def _enabled():
    return os.environ.get("PREDITA_ENABLE_MTN_SUBSCRIPTIONS", "0") == "1"


def _client_id():
    return (
        os.environ.get("MTN_OAUTH_CLIENT_ID")
        or os.environ.get("MTN_PRODUCTION_KEY")
        or ""
    )


def _client_secret():
    return (
        os.environ.get("MTN_OAUTH_CLIENT_SECRET")
        or os.environ.get("MTN_PRODUCTION_SECRET")
        or ""
    )


def _oauth_url():
    return os.environ.get(
        "MTN_OAUTH_URL",
        "https://api.mtn.com/v1/oauth/access_token",
    )


def _subscriptions_url(msisdn_digits):
    template = os.environ.get(
        "MTN_SUBSCRIPTIONS_URL_TEMPLATE",
        "https://api.mtn.com/customers/{msisdn}/subscriptions",
    )
    return template.format(msisdn=quote(msisdn_digits, safe=""))


def _safe_json(response):
    try:
        return response.json()
    except ValueError:
        return {"message": "Provider returned a non-JSON response."}


def _redact(value):
    secret_keys = {
        "access_token", "refresh_token", "authorization", "client_secret",
        "consumer_secret", "password", "token",
    }
    if isinstance(value, dict):
        return {
            key: ("[REDACTED]" if str(key).lower() in secret_keys else _redact(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _get_access_token():
    now = time.monotonic()
    cached = _TOKEN_CACHE.get("access_token")
    if cached and now < float(_TOKEN_CACHE.get("expires_at", 0)):
        return {"ok": True, "access_token": cached, "cached": True}

    client_id = _client_id()
    client_secret = _client_secret()
    if not client_id or not client_secret:
        return {
            "ok": False,
            "status": "missing_credentials",
            "message": "MTN Production Key/Secret are not configured on the server.",
        }

    try:
        response = requests.post(
            _oauth_url(),
            params={"grant_type": "client_credentials"},
            data={"client_id": client_id, "client_secret": client_secret},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=20,
        )
    except requests.RequestException as exc:
        return {
            "ok": False,
            "status": "oauth_network_error",
            "message": f"MTN OAuth request failed: {type(exc).__name__}",
        }

    payload = _safe_json(response)
    token = payload.get("access_token") if isinstance(payload, dict) else None
    if not response.ok or not token:
        safe_error = {}
        if isinstance(payload, dict):
            for key in ("error", "error_description", "status", "message"):
                if key in payload:
                    safe_error[key] = payload[key]
        return {
            "ok": False,
            "status": "oauth_provider_error",
            "http_status": response.status_code,
            "message": safe_error.get("error_description")
            or safe_error.get("message")
            or "MTN OAuth token request was rejected.",
        }

    try:
        expires_in = int(payload.get("expires_in", 3599))
    except (TypeError, ValueError):
        expires_in = 3599

    # Refresh at least 60 seconds before MTN's advertised expiry.
    ttl = max(30, expires_in - 60)
    _TOKEN_CACHE["access_token"] = token
    _TOKEN_CACHE["expires_at"] = now + ttl
    return {"ok": True, "access_token": token, "cached": False}


def _query_subscriptions(normalized_phone):
    if not _enabled():
        return {
            "ok": False,
            "status": "disabled",
            "message": "MTN Subscriptions v2 is disabled on this server.",
        }

    if not normalized_phone or not re.fullmatch(r"\+27\d{9}", normalized_phone):
        return {
            "ok": False,
            "status": "invalid_msisdn",
            "message": "Enter a valid South African mobile number.",
        }

    oauth = _get_access_token()
    if not oauth.get("ok"):
        return oauth

    msisdn_digits = normalized_phone[1:]
    try:
        response = requests.get(
            _subscriptions_url(msisdn_digits),
            headers={
                "Authorization": f"Bearer {oauth['access_token']}",
                "Accept": "application/json",
            },
            timeout=20,
        )
    except requests.RequestException as exc:
        return {
            "ok": False,
            "status": "network_error",
            "message": f"MTN subscriptions request failed: {type(exc).__name__}",
            "http_status": None,
        }

    payload = _redact(_safe_json(response))
    provider_transaction_id = (
        response.headers.get("transactionId")
        or response.headers.get("x-transaction-id")
        or response.headers.get("x-request-id")
    )
    if isinstance(payload, dict):
        provider_transaction_id = (
            provider_transaction_id
            or payload.get("transactionId")
            or payload.get("requestId")
        )

    return {
        "ok": response.ok,
        "status": "success" if response.ok else "provider_error",
        "http_status": response.status_code,
        "provider_transaction_id": provider_transaction_id,
        "data": payload,
        "message": None if response.ok else "MTN subscriptions request was rejected.",
    }


def register_mtn_subscriptions(app, core):
    nav_marker = '<a href="{{ url_for(\'home\') }}">Cases</a>'
    nav_link = (
        nav_marker
        + "\n    {% if can('provider_check') %}"
          '<a href="{{ url_for(\'mtn_subscriptions_page\') }}">MTN Subscriptions</a>'
          "{% endif %}"
    )
    if "mtn_subscriptions_page" not in core.BASE_HTML:
        core.BASE_HTML = core.BASE_HTML.replace(nav_marker, nav_link)

    @app.route("/mtn/subscriptions", methods=["GET", "POST"], endpoint="mtn_subscriptions_page")
    @core.require_permission("provider_check")
    def mtn_subscriptions_page():
        con = core.db()
        cases = con.execute(
            "SELECT case_id, authority_ref, title, status FROM cases "
            "ORDER BY created_at DESC LIMIT 200"
        ).fetchall()
        result = None
        selected_case_id = ""
        msisdn_input = ""

        if request.method == "POST":
            core.check_csrf()
            selected_case_id = request.form.get("case_id", "").strip()
            msisdn_input = request.form.get("msisdn", "").strip()
            authority_confirmed = request.form.get("authority_confirmed") == "yes"

            case = core.require_case(selected_case_id)
            normalized = core.normalize_phone(msisdn_input)

            if not authority_confirmed:
                flash(
                    "Confirm that the case authority and MTN product agreement cover this query.",
                    "error",
                )
            elif not normalized or not re.fullmatch(r"\+27\d{9}", normalized):
                flash("Enter a valid South African mobile number.", "error")
            else:
                result = _query_subscriptions(normalized)
                safe_result = _redact(result.get("data", {}))
                result_json = json.dumps(safe_result, ensure_ascii=False)
                if len(result_json) > 200000:
                    result_json = json.dumps({
                        "truncated": True,
                        "message": "Provider response exceeded Predita's 200 KB storage limit.",
                    })

                con.execute(
                    """
                    INSERT INTO provider_checks(
                      case_id,provider,capability,msisdn_norm,checked_at,requested_by,
                      http_status,provider_transaction_id,result_status,result_json
                    ) VALUES(?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        selected_case_id,
                        "MTN",
                        "subscriptions_v2",
                        normalized,
                        core.now_iso(),
                        session.get("user", "unknown"),
                        result.get("http_status"),
                        result.get("provider_transaction_id"),
                        result.get("status", "unknown"),
                        result_json,
                    ),
                )
                con.commit()
                core.audit(
                    "mtn_subscriptions_query",
                    selected_case_id,
                    f"msisdn={normalized}; status={result.get('status', 'unknown')}",
                )

                if result.get("ok"):
                    flash("MTN subscriptions query completed and was recorded in the case audit trail.")
                else:
                    flash(result.get("message") or "MTN subscriptions query failed.", "error")

        recent = con.execute(
            """
            SELECT case_id,msisdn_norm,checked_at,http_status,result_status,provider_transaction_id
            FROM provider_checks
            WHERE provider='MTN' AND capability='subscriptions_v2'
            ORDER BY checked_at DESC LIMIT 20
            """
        ).fetchall()

        body = """
        <div class="card">
          <h2>MTN Subscriptions v2</h2>
          <p class="small">
            Case-bound operator query. Use only where the selected case authority and your
            MTN commercial/API agreement permit this MSISDN lookup. OAuth credentials remain
            server-side and are never displayed or stored in the case record.
          </p>
          <p><span class="badge">{{ 'Enabled' if enabled else 'Disabled' }}</span></p>
          <form method="post">
            <input type="hidden" name="csrf" value="{{ csrf_token() }}">
            <label>Authorized case</label>
            <select name="case_id" required>
              <option value="">Select case</option>
              {% for c in cases %}
                <option value="{{ c['case_id'] }}" {{ 'selected' if c['case_id']==selected_case_id else '' }}>
                  {{ c['case_id'] }} · {{ c['authority_ref'] }}{% if c['title'] %} · {{ c['title'] }}{% endif %}
                </option>
              {% endfor %}
            </select>
            <label>South African MTN number</label>
            <input name="msisdn" value="{{ msisdn_input }}" placeholder="0821234567" required>
            <label>
              <input style="width:auto" type="checkbox" name="authority_confirmed" value="yes" required>
              I confirm the case authority and MTN product agreement cover this query.
            </label>
            <button type="submit">Query MTN subscriptions</button>
          </form>
        </div>

        {% if result %}
        <div class="card">
          <h3>Latest result</h3>
          <p>Status: <span class="badge">{{ result.get('status') }}</span>
             {% if result.get('http_status') %} HTTP {{ result.get('http_status') }}{% endif %}</p>
          <pre style="white-space:pre-wrap;overflow:auto">{{ result_display }}</pre>
        </div>
        {% endif %}

        <div class="card">
          <h3>Recent MTN subscription checks</h3>
          <table>
            <tr><th>Time</th><th>Case</th><th>MSISDN</th><th>Status</th><th>HTTP</th><th>Provider ref</th></tr>
            {% for row in recent %}
              <tr>
                <td>{{ row['checked_at'] }}</td><td>{{ row['case_id'] }}</td>
                <td>{{ row['msisdn_norm'] }}</td><td>{{ row['result_status'] }}</td>
                <td>{{ row['http_status'] or '' }}</td><td>{{ row['provider_transaction_id'] or '' }}</td>
              </tr>
            {% else %}
              <tr><td colspan="6" class="small">No MTN subscription checks recorded yet.</td></tr>
            {% endfor %}
          </table>
        </div>
        """

        result_display = ""
        if result is not None:
            display_obj = {
                "status": result.get("status"),
                "http_status": result.get("http_status"),
                "provider_transaction_id": result.get("provider_transaction_id"),
                "data": _redact(result.get("data", {})),
            }
            result_display = json.dumps(display_obj, indent=2, ensure_ascii=False)

        return core.render_page(
            "MTN Subscriptions",
            body,
            cases=cases,
            recent=recent,
            result=result,
            result_display=result_display,
            selected_case_id=selected_case_id,
            msisdn_input=msisdn_input,
            enabled=_enabled(),
            csrf_token=core.csrf_token,
        )
