from urllib.parse import quote
from flask import Blueprint, jsonify, make_response, redirect, request
from auth import get_authenticated_user, require_roles
from validators import ApiError
from .auth_service import SecurityAuthService
from .admin_service import SecurityAdminService
from .oidc_google import (
    GoogleOidcService,
    OIDC_STATE_COOKIE_NAME,
    OIDC_STATE_MAX_AGE,
)

security_bp = Blueprint("security", __name__)


def get_client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    return forwarded or request.remote_addr or "127.0.0.1"


@security_bp.route("/api/auth/register", methods=["POST"])
def register():
    result = SecurityAuthService.register_user(
        request.get_json(silent=True) or {},
        remote_ip=get_client_ip(),
        base_url=request.host_url.rstrip("/"),
    )
    return jsonify(result), 201


@security_bp.route("/auth/activate", methods=["GET"])
def activate_account_page():
    token = request.args.get("token", "").strip()
    try:
        result = SecurityAuthService.activate_account(token)
        return redirect(f"/?activation=success&msg={quote(result['message'])}")
    except ApiError as err:
        return redirect(f"/?activation=error&msg={quote(err.message)}")


@security_bp.route("/api/auth/activate", methods=["POST"])
def activate_account_api():
    data = request.get_json(silent=True) or {}
    result = SecurityAuthService.activate_account(data.get("token", ""))
    return jsonify(result), 200


@security_bp.route("/api/auth/resend-activation", methods=["POST"])
def resend_activation():
    user = get_authenticated_user()
    result = SecurityAuthService.resend_activation(
        user,
        base_url=request.host_url.rstrip("/"),
    )
    return jsonify(result), 200


@security_bp.route("/api/auth/password-reset/request", methods=["POST"])
def request_password_reset():
    result = SecurityAuthService.request_password_reset(
        request.get_json(silent=True) or {},
        base_url=request.host_url.rstrip("/"),
    )
    return jsonify(result), 200


@security_bp.route("/auth/reset-password", methods=["GET"])
def password_reset_page():
    token = request.args.get("token", "").strip()
    try:
        info = SecurityAuthService.validate_password_reset_token(token)
        return redirect(
            f"/#reset_status=valid&token={quote(token)}&email={quote(info['email_masked'])}"
        )
    except ApiError as err:
        return redirect(f"/#reset_status=error&msg={quote(err.message)}")


@security_bp.route("/api/auth/password-reset/confirm", methods=["POST"])
def confirm_password_reset():
    result = SecurityAuthService.confirm_password_reset(request.get_json(silent=True) or {})
    return jsonify(result), 200


@security_bp.route("/api/auth/login", methods=["POST"])
def login():
    result = SecurityAuthService.login_user(
        request.get_json(silent=True) or {},
        remote_ip=get_client_ip(),
        user_agent=(request.headers.get("User-Agent", "") or "")[:255],
    )
    return jsonify(result), 200


@security_bp.route("/api/auth/2fa/verify", methods=["POST"])
def verify_two_factor():
    result = SecurityAuthService.verify_two_factor_login(
        request.get_json(silent=True) or {},
        remote_ip=get_client_ip(),
        user_agent=(request.headers.get("User-Agent", "") or "")[:255],
    )
    return jsonify(result), 200


@security_bp.route("/api/auth/2fa/resend", methods=["POST"])
def resend_two_factor():
    result = SecurityAuthService.resend_two_factor_code(request.get_json(silent=True) or {})
    return jsonify(result), 200


@security_bp.route("/api/auth/2fa/toggle", methods=["POST"])
def toggle_two_factor():
    user = get_authenticated_user()
    data = request.get_json(silent=True) or {}
    if "enabled" not in data:
        raise ApiError(400, "Необхідно передати булеве поле enabled (true або false).")
    result = SecurityAuthService.toggle_two_factor(user, bool(data["enabled"]))
    return jsonify(result), 200


@security_bp.route("/auth/google/login", methods=["GET"])
def google_oidc_login():
    try:
        auth_url, csrf_token = GoogleOidcService.create_authorization_request(
            base_url=request.host_url.rstrip("/"),
        )
    except ApiError as err:
        return redirect(f"/#oidc_status=error&msg={quote(err.message)}")

    response = make_response(redirect(auth_url))
    response.set_cookie(
        OIDC_STATE_COOKIE_NAME,
        csrf_token,
        max_age=OIDC_STATE_MAX_AGE,
        httponly=True,
        samesite="Lax",
        secure=request.is_secure,
    )
    return response


@security_bp.route("/auth/google/callback", methods=["GET"])
def google_oidc_callback():
    oauth_error = request.args.get("error", "").strip()
    if oauth_error:
        resp = make_response(
            redirect(f"/#oidc_status=error&msg={quote('Вхід через Google скасовано користувачем.')}")
        )
        resp.delete_cookie(OIDC_STATE_COOKIE_NAME)
        return resp

    code = request.args.get("code", "").strip()
    state_param = request.args.get("state", "").strip()
    cookie_csrf = request.cookies.get(OIDC_STATE_COOKIE_NAME, "").strip()

    try:
        result = GoogleOidcService.handle_callback(
            code=code,
            state_param=state_param,
            cookie_csrf=cookie_csrf,
            base_url=request.host_url.rstrip("/"),
            remote_ip=get_client_ip(),
            user_agent=(request.headers.get("User-Agent", "") or "")[:255],
        )
        if result.get("requires_2fa"):
            target = (
                f"/#oidc_status=2fa"
                f"&challenge={quote(result['challenge_token'])}"
                f"&msg={quote(result['message'])}"
            )
        else:
            target = (
                f"/#oidc_status=success"
                f"&token={quote(result['token'])}"
                f"&msg={quote(result['message'])}"
            )
    except ApiError as err:
        target = f"/#oidc_status=error&msg={quote(err.message)}"

    resp = make_response(redirect(target))
    resp.delete_cookie(OIDC_STATE_COOKIE_NAME)
    return resp


@security_bp.route("/api/auth/me", methods=["GET"])
def get_me():
    user = get_authenticated_user()
    return jsonify(SecurityAuthService.get_profile(user)), 200


@security_bp.route("/api/auth/logout", methods=["POST"])
def logout():
    return jsonify({"status": 200, "message": "Ви вийшли з облікового запису."}), 200


@security_bp.route("/api/admin/users", methods=["GET"])
@require_roles("admin")
def admin_list_users():
    return jsonify({"status": 200, "users": SecurityAdminService.list_users()}), 200


@security_bp.route("/api/admin/users/<int:user_id>/block", methods=["PATCH"])
@require_roles("admin")
def admin_block_user(user_id: int):
    data = request.get_json(silent=True) or {}
    if "is_blocked" not in data:
        raise ApiError(400, "Необхідно передати поле is_blocked (0 або 1).")
    result = SecurityAdminService.set_user_blocked(
        target_user_id=user_id,
        is_blocked=int(data["is_blocked"]),
        current_admin=request.current_user,
    )
    return jsonify(result), 200


@security_bp.route("/api/admin/login-logs", methods=["GET"])
@require_roles("admin")
def admin_login_logs():
    limit = request.args.get("limit", 100, type=int)
    email_filter = request.args.get("email", "")
    result = SecurityAdminService.get_login_logs(limit=limit, email_filter=email_filter)
    return jsonify(result), 200
