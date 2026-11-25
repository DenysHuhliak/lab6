(function () {
    const $ = (id) => document.getElementById(id);

    let pending2faChallenge = null;

    const ROLE_LABELS = {
        admin: "Адміністратор",
        teacher: "Викладач",
        student: "Студент",
    };

    const COMMON_WEAK = new Set([
        "password", "password1", "password1!", "password123", "password123!",
        "qwerty123", "qwerty123!", "12345678", "123456789", "admin123",
        "admin123!", "p@ssw0rd", "passw0rd", "pnu12345!", "student1!", "teacher1!"
    ]);

    function escapeHtml(value) {
        return String(value ?? "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
    }

    function formatUtcDateTime(sqlTimestamp) {
        if (!sqlTimestamp) return "—";
        const iso = sqlTimestamp.includes("T") ? sqlTimestamp : `${sqlTimestamp.replace(" ", "T")}Z`;
        const date = new Date(iso);
        if (Number.isNaN(date.getTime())) return sqlTimestamp;
        return date.toLocaleString("uk-UA", {
            year: "numeric",
            month: "2-digit",
            day: "2-digit",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
        });
    }

    function getRecaptchaToken() {
        if (window.grecaptcha && typeof window.grecaptcha.getResponse === "function") {
            return window.grecaptcha.getResponse();
        }
        return "";
    }

    function resetRecaptcha() {
        if (window.grecaptcha && typeof window.grecaptcha.reset === "function") {
            try {
                window.grecaptcha.reset();
            } catch {
  
            }
        }
    }

    function showAuthStep(mode) {
        const isLogin = mode === "login";
        const isRegister = mode === "register";
        const isTwoFa = mode === "twofa";

        $("auth-tabs-bar")?.classList.toggle("hidden", isTwoFa);
        $("oidc-auth-block")?.classList.toggle("hidden", isTwoFa);
        $("login-form")?.classList.toggle("hidden", !isLogin);
        $("register-form")?.classList.toggle("hidden", !isRegister);
        $("twofa-form")?.classList.toggle("hidden", !isTwoFa);

        $("login-error-msg")?.classList.add("hidden");
        $("reg-error-msg")?.classList.add("hidden");
        $("twofa-error-msg")?.classList.add("hidden");

        if ($("auth-modal-title")) {
            $("auth-modal-title").textContent = isTwoFa
                ? "Двофакторна автентифікація (2FA)"
                : "Автентифікація в системі КНУ";
        }

        if ($("tab-login-btn")) $("tab-login-btn").className = isLogin ? "btn-primary-pnu" : "btn-outline-pnu";
        if ($("tab-register-btn")) $("tab-register-btn").className = isRegister ? "btn-primary-pnu" : "btn-outline-pnu";
    }

    function openLoginModal() {
        pending2faChallenge = null;
        $("login-form")?.reset?.();
        $("register-form")?.reset?.();
        $("twofa-form")?.reset?.();
        showAuthStep("login");
        $("auth-modal")?.classList.remove("hidden");
    }

    function openTwoFactorStep(challengeToken, message) {
        pending2faChallenge = challengeToken;
        if ($("twofa-info-box")) {
            $("twofa-info-box").textContent =
                message || "На вашу електронну пошту надіслано 6-значний код підтвердження.";
        }
        if ($("twofa-code")) $("twofa-code").value = "";
        showAuthStep("twofa");
        $("auth-modal")?.classList.remove("hidden");
        $("twofa-code")?.focus();
    }

    function evaluatePasswordClient(password, email) {
        const pwd = password || "";
        const rules = {
            length: pwd.length >= 8,
            upper: /\p{Lu}/u.test(pwd),
            lower: /\p{Ll}/u.test(pwd),
            digit: /\d/.test(pwd),
            special: /[^\p{L}\p{N}\s]/u.test(pwd),
        };

        const norm = pwd.trim().toLowerCase();
        const emailLocal = (email || "").split("@")[0].trim().toLowerCase();
        const isCommon = COMMON_WEAK.has(norm) || (emailLocal.length >= 4 && norm.includes(emailLocal));

        let score = Object.values(rules).filter(Boolean).length;
        if (pwd.length >= 12 && score === 5) score += 1;
        if (isCommon && pwd.length > 0) score = Math.min(score, 1);

        let level = "empty";
        let label = "Введіть пароль";
        let percent = 0;

        if (pwd.length > 0) {
            if (score <= 2) {
                level = "weak";
                label = isCommon ? "Слабкий (поширений або містить email)" : "Слабкий";
                percent = 25;
            } else if (score <= 4) {
                level = "medium";
                label = "Середній";
                percent = 60;
            } else if (score === 5) {
                level = "strong";
                label = "Надійний";
                percent = 85;
            } else {
                level = "very-strong";
                label = "Дуже надійний";
                percent = 100;
            }
        }

        return { rules, level, label, percent };
    }

    function renderPasswordMeter(pwdInputId, emailInputId, barId, textId, rulePrefix) {
        const pwdInput = $(pwdInputId);
        const emailInput = emailInputId ? $(emailInputId) : null;
        const bar = $(barId);
        const text = $(textId);
        if (!pwdInput || !bar || !text) return;

        const res = evaluatePasswordClient(pwdInput.value, emailInput ? emailInput.value : "");
        bar.style.width = `${res.percent}%`;
        bar.className = `strength-fill strength-${res.level}`;
        text.textContent = res.label;
        text.className = `strength-label text-${res.level}`;

        const mapping = {
            [`${rulePrefix}length`]: res.rules.length,
            [`${rulePrefix}upper`]: res.rules.upper,
            [`${rulePrefix}lower`]: res.rules.lower,
            [`${rulePrefix}digit`]: res.rules.digit,
            [`${rulePrefix}special`]: res.rules.special,
        };
        Object.entries(mapping).forEach(([id, passed]) => {
            const el = $(id);
            if (el) {
                el.classList.toggle("rule-ok", passed);
                el.classList.toggle("rule-fail", !passed && pwdInput.value.length > 0);
            }
        });
    }

    function updatePasswordMeter() {
        renderPasswordMeter(
            "reg-password",
            "reg-email",
            "password-strength-bar",
            "password-strength-text",
            "pw-rule-"
        );
    }

    function updateResetPasswordMeter() {
        renderPasswordMeter(
            "reset-new-password",
            null,
            "reset-password-strength-bar",
            "reset-password-strength-text",
            "reset-pw-rule-"
        );
    }

    function openResetModal(mode, token = "", emailMasked = "") {
        const modal = $("reset-password-modal");
        if (!modal) return;

        const isConfirm = mode === "confirm";
        $("reset-request-form")?.reset?.();
        $("reset-confirm-form")?.reset?.();
        $("reset-req-error-msg")?.classList.add("hidden");
        $("reset-confirm-error-msg")?.classList.add("hidden");

        $("reset-request-form")?.classList.toggle("hidden", isConfirm);
        $("reset-confirm-form")?.classList.toggle("hidden", !isConfirm);

        if ($("reset-modal-title")) {
            $("reset-modal-title").textContent = isConfirm
                ? "Встановлення нового пароля"
                : "Відновлення пароля";
        }

        if (isConfirm) {
            if ($("reset-token-input")) $("reset-token-input").value = token;
            if ($("reset-confirm-info")) {
                $("reset-confirm-info").textContent = emailMasked
                    ? `Встановіть новий пароль для облікового запису ${emailMasked}.`
                    : "Встановіть новий пароль для вашого облікового запису.";
            }
            updateResetPasswordMeter();
        } else {
            const typedEmail = ($("login-email")?.value || "").trim();
            if (typedEmail && $("reset-req-email")) {
                $("reset-req-email").value = typedEmail;
            }
        }

        modal.classList.remove("hidden");
    }

    function closeResetModal() {
        $("reset-password-modal")?.classList.add("hidden");
        $("reset-request-form")?.reset?.();
        $("reset-confirm-form")?.reset?.();
        updateResetPasswordMeter();
    }

    function initResetPasswordModal() {
        const core = window.AppCore;
        if (!core) return;

        if ($("open-forgot-password-btn")) {
            $("open-forgot-password-btn").onclick = () => {
                $("auth-modal")?.classList.add("hidden");
                openResetModal("request");
            };
        }

        if ($("reset-close-btn")) $("reset-close-btn").onclick = closeResetModal;
        if ($("reset-req-cancel-btn")) $("reset-req-cancel-btn").onclick = closeResetModal;
        if ($("reset-confirm-cancel-btn")) $("reset-confirm-cancel-btn").onclick = closeResetModal;
        if ($("reset-new-password")) {
            $("reset-new-password").addEventListener("input", updateResetPasswordMeter);
        }

        if ($("reset-request-form")) {
            $("reset-request-form").onsubmit = async (e) => {
                e.preventDefault();
                const errorEl = $("reset-req-error-msg");
                const submitBtn = $("reset-req-submit-btn");
                errorEl?.classList.add("hidden");

                const email = ($("reset-req-email")?.value || "").trim();
                if (submitBtn) {
                    submitBtn.disabled = true;
                    submitBtn.textContent = "Надсилання...";
                }
                try {
                    const { ok, data } = await core.apiFetch("/api/auth/password-reset/request", {
                        method: "POST",
                        body: JSON.stringify({ email }),
                    });
                    if (!ok) {
                        errorEl.textContent = data.error || data.message || "Помилка запиту відновлення.";
                        errorEl.classList.remove("hidden");
                        return;
                    }
                    core.showToast(data.message || "Лист із посиланням відновлення надіслано.", "success");
                    closeResetModal();
                } catch {
                    errorEl.textContent = "Не вдалося з'єднатися з сервером.";
                    errorEl.classList.remove("hidden");
                } finally {
                    if (submitBtn) {
                        submitBtn.disabled = false;
                        submitBtn.textContent = "Надіслати посилання";
                    }
                }
            };
        }

        if ($("reset-confirm-form")) {
            $("reset-confirm-form").onsubmit = async (e) => {
                e.preventDefault();
                const errorEl = $("reset-confirm-error-msg");
                const submitBtn = $("reset-confirm-submit-btn");
                errorEl?.classList.add("hidden");

                const token = ($("reset-token-input")?.value || "").trim();
                const newPassword = $("reset-new-password")?.value || "";
                const confirmPassword = $("reset-confirm-password")?.value || "";

                if (newPassword !== confirmPassword) {
                    errorEl.textContent = "Пароль і його підтвердження не співпадають.";
                    errorEl.classList.remove("hidden");
                    return;
                }

                if (submitBtn) {
                    submitBtn.disabled = true;
                    submitBtn.textContent = "Збереження...";
                }
                try {
                    const { ok, data } = await core.apiFetch("/api/auth/password-reset/confirm", {
                        method: "POST",
                        body: JSON.stringify({
                            token,
                            new_password: newPassword,
                            confirm_password: confirmPassword,
                        }),
                    });
                    if (!ok) {
                        errorEl.textContent = data.error || data.message || "Не вдалося оновити пароль.";
                        errorEl.classList.remove("hidden");
                        return;
                    }
                    core.showToast(data.message || "Пароль успішно змінено!", "success");
                    closeResetModal();
                    openLoginModal();
                } catch {
                    errorEl.textContent = "Не вдалося з'єднатися з сервером.";
                    errorEl.classList.remove("hidden");
                } finally {
                    if (submitBtn) {
                        submitBtn.disabled = false;
                        submitBtn.textContent = "Зберегти новий пароль";
                    }
                }
            };
        }
    }

    async function resendActivationEmail(btn) {
        const core = window.AppCore;
        if (!core) return;
        if (btn) {
            btn.disabled = true;
            btn.textContent = "Надсилання...";
        }
        try {
            const { ok, data } = await core.apiFetch("/api/auth/resend-activation", { method: "POST" });
            core.showToast(
                data.message || data.error || (ok ? "Лист надіслано." : "Помилка надсилання."),
                ok ? "success" : "error"
            );
        } catch {
            core.showToast("Не вдалося з'єднатися з сервером.", "error");
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.textContent = "Надіслати лист активації повторно";
            }
        }
    }

    async function toggleTwoFactor(enable, btn) {
        const core = window.AppCore;
        if (!core) return;
        if (btn) btn.disabled = true;
        try {
            const { ok, data } = await core.apiFetch("/api/auth/2fa/toggle", {
                method: "POST",
                body: JSON.stringify({ enabled: enable }),
            });
            if (!ok) {
                core.showToast(data.error || data.message || "Не вдалося змінити налаштування 2FA.", "error");
                return;
            }
            if (data.user) {
                core.updateStoredUser(data.user);
                renderProfile(data.user);
            }
            core.showToast(data.message, enable ? "success" : "warning");
        } catch {
            core.showToast("Не вдалося з'єднатися з сервером.", "error");
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    function renderProfile(user) {
        if (!user) return;
        if ($("profile-full-name")) $("profile-full-name").textContent = user.full_name || "—";
        if ($("profile-email")) $("profile-email").textContent = user.email || "—";
        if ($("profile-role")) $("profile-role").textContent = ROLE_LABELS[user.role] || user.role;

        if ($("profile-auth-method")) {
            $("profile-auth-method").textContent = user.oauth_provider
                ? `OpenID Connect (${user.oauth_provider.toUpperCase()})`
                : "Локальний акаунт (PBKDF2-SHA256)";
        }

        const isVerified = Boolean(user.is_verified);
        const verifiedBadge = $("profile-verified-badge");
        if (verifiedBadge) {
            verifiedBadge.textContent = isVerified ? "Активовано" : "Не активовано";
            verifiedBadge.className = `badge-status ${isVerified ? "badge-free" : "badge-queued"}`;
        }

        const is2fa = Boolean(user.two_factor_enabled);
        const twoFaBadge = $("profile-2fa-badge");
        if (twoFaBadge) {
            twoFaBadge.textContent = is2fa ? "Увімкнено (Email OTP)" : "Вимкнено";
            twoFaBadge.className = `badge-status ${is2fa ? "badge-free" : "badge-closed"}`;
        }

        const actionsBox = $("profile-security-actions");
        if (actionsBox) {
            actionsBox.innerHTML = "";

            if (!isVerified) {
                const hint = document.createElement("div");
                hint.className = "occupancy-alert badge-queued";
                hint.innerHTML =
                    "<strong>Потрібна активація:</strong> перевірте корпоративну пошту та перейдіть за одноразовим посиланням із листа.";

                const resendBtn = document.createElement("button");
                resendBtn.type = "button";
                resendBtn.id = "btn-resend-activation";
                resendBtn.className = "btn-primary-pnu";
                resendBtn.textContent = "Надіслати лист активації повторно";
                resendBtn.onclick = () => resendActivationEmail(resendBtn);

                actionsBox.appendChild(hint);
                actionsBox.appendChild(resendBtn);
            } else {
                const okHint = document.createElement("div");
                okHint.className = "occupancy-alert badge-free";
                okHint.textContent = "Електронну пошту підтверджено. Обліковий запис повністю активовано.";
                actionsBox.appendChild(okHint);
            }

            const twoFaCard = document.createElement("div");
            twoFaCard.className = "profile-2fa-box";

            const twoFaDesc = document.createElement("p");
            twoFaDesc.className = "profile-2fa-desc";
            twoFaDesc.textContent = is2fa
                ? "Під час кожного входу на вашу пошту надсилається одноразовий 6-значний код підтвердження."
                : "Додайте додатковий рівень захисту: при вході система вимагатиме 6-значний код із вашої пошти.";

            const toggle2faBtn = document.createElement("button");
            toggle2faBtn.type = "button";
            toggle2faBtn.id = "btn-toggle-2fa";
            toggle2faBtn.className = is2fa ? "btn-outline-pnu" : "btn-primary-pnu";
            toggle2faBtn.textContent = is2fa ? "Вимкнути 2FA" : "Увімкнути 2FA (Email OTP)";
            if (!isVerified && !is2fa) {
                toggle2faBtn.title = "Спочатку активуйте обліковий запис через електронну пошту";
            }
            toggle2faBtn.onclick = () => toggleTwoFactor(!is2fa, toggle2faBtn);

            twoFaCard.appendChild(twoFaDesc);
            twoFaCard.appendChild(toggle2faBtn);
            actionsBox.appendChild(twoFaCard);
        }
    }

    async function loadProfile() {
        const core = window.AppCore;
        if (!core || !core.getAuthToken()) return;
        const { ok, data } = await core.apiFetch("/api/auth/me");
        if (ok && data.user) {
            core.updateStoredUser(data.user);
            renderProfile(data.user);
        }
    }

    async function toggleUserBlock(userId, isBlocked) {
        const core = window.AppCore;
        if (!core) return;
        try {
            const { ok, data } = await core.apiFetch(`/api/admin/users/${userId}/block`, {
                method: "PATCH",
                body: JSON.stringify({ is_blocked: isBlocked }),
            });
            core.showToast(
                data.message || data.error || (ok ? "Статус оновлено." : "Помилка оновлення."),
                ok ? (isBlocked ? "warning" : "success") : "error"
            );
            if (ok) loadAdminPanel();
        } catch {
            core.showToast("Не вдалося з'єднатися з сервером.", "error");
        }
    }

    function renderAdminUsers(users) {
        const tbody = $("admin-users-body");
        const core = window.AppCore;
        if (!tbody || !core) return;

        const activeAdmin = core.getCurrentUser();
        tbody.innerHTML = "";

        if (!users.length) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:14px; color:#6c757d;">Користувачів не знайдено.</td></tr>`;
            return;
        }

        users.forEach((u) => {
            const tr = document.createElement("tr");

            const verifiedBadge = u.is_verified
                ? `<span class="badge-status badge-free">Активовано</span>`
                : `<span class="badge-status badge-queued">Не активовано</span>`;
            const twoFaBadge = u.two_factor_enabled
                ? `<span class="badge-status badge-info">2FA: Увімк.</span>`
                : `<span class="badge-status badge-closed">2FA: Вимк.</span>`;

            let accessBadge = `<span class="badge-status badge-free">Активний</span>`;
            if (u.is_blocked) {
                accessBadge = `<span class="badge-status badge-occupied">Заблоковано адміном</span>`;
            } else if (u.is_temporarily_locked) {
                accessBadge = `<span class="badge-status badge-queued" title="До ${escapeHtml(formatUtcDateTime(u.locked_until))}">Тимч. блок (Brute Force)</span>`;
            }

            const isSelf = activeAdmin && activeAdmin.id === u.id;
            let actionsHtml = `<span style="color:#6c757d; font-size:12px;">Поточний адмін</span>`;
            if (!isSelf) {
                if (u.is_blocked) {
                    actionsHtml = `<button type="button" class="btn-action-sm btn-book" data-action="unblock">Розблокувати</button>`;
                } else if (u.is_temporarily_locked) {
                    actionsHtml = `
                        <div class="admin-action-group">
                            <button type="button" class="btn-action-sm btn-book" data-action="unblock">Зняти блок</button>
                            <button type="button" class="btn-action-sm btn-danger-sm" data-action="block">Заблокувати</button>
                        </div>
                    `;
                } else {
                    actionsHtml = `<button type="button" class="btn-action-sm btn-danger-sm" data-action="block">Заблокувати</button>`;
                }
            }

            tr.innerHTML = `
                <td>
                    <strong>${escapeHtml(u.full_name)}</strong>
                    <div class="admin-subtext">${escapeHtml(u.email)}</div>
                </td>
                <td>${escapeHtml(ROLE_LABELS[u.role] || u.role)}</td>
                <td><div class="admin-badges-col">${verifiedBadge}${twoFaBadge}</div></td>
                <td>${accessBadge}</td>
                <td>
                    <strong>${u.failed_login_attempts || 0}</strong> підряд
                    <div class="admin-subtext">Усього невдалих: ${u.failed_login_total || 0}</div>
                </td>
                <td>${actionsHtml}</td>
            `;

            const blockBtn = tr.querySelector('[data-action="block"]');
            if (blockBtn) blockBtn.onclick = () => toggleUserBlock(u.id, 1);

            const unblockBtn = tr.querySelector('[data-action="unblock"]');
            if (unblockBtn) unblockBtn.onclick = () => toggleUserBlock(u.id, 0);

            tbody.appendChild(tr);
        });
    }

    function renderAdminLoginLogs(logs, summary) {
        const summaryBody = $("admin-logs-summary-body");
        if (summaryBody) {
            summaryBody.innerHTML = "";
            if (!summary.length) {
                summaryBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:12px; color:#6c757d;">Спроб входу ще не зафіксовано.</td></tr>`;
            } else {
                summary.forEach((s) => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td><strong>${escapeHtml(s.email)}</strong></td>
                        <td>${s.total_attempts}</td>
                        <td><span class="badge-status badge-free">${s.success_attempts}</span></td>
                        <td><span class="badge-status ${s.failed_attempts > 0 ? "badge-occupied" : "badge-closed"}">${s.failed_attempts}</span></td>
                        <td>${escapeHtml(formatUtcDateTime(s.last_attempt))}</td>
                    `;
                    summaryBody.appendChild(tr);
                });
            }
        }

        const logsBody = $("admin-logs-body");
        if (logsBody) {
            logsBody.innerHTML = "";
            if (!logs.length) {
                logsBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:12px; color:#6c757d;">Журнал входів порожній.</td></tr>`;
            } else {
                logs.forEach((log) => {
                    const tr = document.createElement("tr");
                    const resBadge = log.success
                        ? `<span class="badge-status badge-free">Успішно</span>`
                        : `<span class="badge-status badge-occupied">Невдача</span>`;
                    tr.innerHTML = `
                        <td style="white-space:nowrap;">${escapeHtml(formatUtcDateTime(log.created_at))}</td>
                        <td>
                            <strong>${escapeHtml(log.email)}</strong>
                            ${log.full_name ? `<div class="admin-subtext">${escapeHtml(log.full_name)}</div>` : ""}
                        </td>
                        <td><code>${escapeHtml(log.ip_address)}</code></td>
                        <td>${resBadge}</td>
                        <td>${escapeHtml(log.reason || "—")}</td>
                    `;
                    logsBody.appendChild(tr);
                });
            }
        }
    }

    async function loadAdminPanel() {
        const core = window.AppCore;
        const user = core?.getCurrentUser?.();
        if (!core || !user || user.role !== "admin") return;

        const emailFilter = ($("admin-log-email-filter")?.value || "").trim();
        const logsQuery = new URLSearchParams({ limit: "100" });
        if (emailFilter) logsQuery.set("email", emailFilter);

        try {
            const [usersRes, logsRes] = await Promise.all([
                core.apiFetch("/api/admin/users"),
                core.apiFetch(`/api/admin/login-logs?${logsQuery.toString()}`),
            ]);

            if (usersRes.ok && usersRes.data.users) {
                renderAdminUsers(usersRes.data.users);
            }
            if (logsRes.ok) {
                renderAdminLoginLogs(logsRes.data.logs || [], logsRes.data.summary || []);
            }
        } catch (err) {
            console.error("Помилка завантаження панелі адміністратора:", err);
            core.showToast("Не вдалося завантажити дані панелі адміністратора.", "error");
        }
    }

    async function performLogout() {
        const core = window.AppCore;
        if (!core) return;
        try {
            await core.apiFetch("/api/auth/logout", { method: "POST" });
        } catch {

        }
        core.clearSession();
        core.showToast("Ви вийшли з облікового запису.", "warning");
    }

    async function handleUrlCallbacks() {
        const core = window.AppCore;
        if (!core) return;

        const queryParams = new URLSearchParams(window.location.search);
        const activationStatus = queryParams.get("activation");
        if (activationStatus) {
            const msg = queryParams.get("msg");
            if (activationStatus === "success") {
                core.showToast(msg || "Обліковий запис успішно активовано!", "success");
                if (core.getAuthToken()) {
                    await loadProfile();
                    core.setActiveView("profile");
                }
            } else {
                core.showToast(msg || "Не вдалося активувати обліковий запис.", "error");
            }
            window.history.replaceState({}, document.title, window.location.pathname);
        }

        if (window.location.hash && window.location.hash.length > 1) {
            const hashParams = new URLSearchParams(window.location.hash.slice(1));
            const oidcStatus = hashParams.get("oidc_status");
            const resetStatus = hashParams.get("reset_status");

            if (oidcStatus || resetStatus) {
                window.history.replaceState({}, document.title, window.location.pathname);
            }

            if (oidcStatus) {
                const msg = hashParams.get("msg");
                if (oidcStatus === "success") {
                    const token = hashParams.get("token");
                    if (token) {
                        try {
                            const { ok, data } = await core.apiFetch("/api/auth/me", {
                                headers: { Authorization: `Bearer ${token}` },
                            });
                            if (ok && data.user) {
                                core.setSession(data.user, token);
                                renderProfile(data.user);
                                core.showToast(msg || `Вітаємо, ${data.user.full_name}!`, "success");
                            } else {
                                core.showToast(data.error || "Не вдалося завершити вхід через Google.", "error");
                            }
                        } catch {
                            core.showToast("Не вдалося завантажити профіль після входу через Google.", "error");
                        }
                    }
                } else if (oidcStatus === "2fa") {
                    const challenge = hashParams.get("challenge");
                    if (challenge) {
                        openTwoFactorStep(challenge, msg);
                        core.showToast(msg || "Введіть 6-значний код із пошти.", "warning");
                    }
                } else {
                    core.showToast(msg || "Помилка входу через Google.", "error");
                }
            }

            if (resetStatus) {
                if (resetStatus === "valid") {
                    const token = hashParams.get("token") || "";
                    const emailMasked = hashParams.get("email") || "";
                    openResetModal("confirm", token, emailMasked);
                } else {
                    const msg = hashParams.get("msg");
                    core.showToast(msg || "Посилання для відновлення пароля недійсне або застаріло.", "error");
                }
            }
        }
    }

    function initSecurityAuthModal() {
        const core = window.AppCore;
        const modal = $("auth-modal");
        if (!core || !modal) return;

        const closeModal = () => {
            pending2faChallenge = null;
            $("twofa-form")?.reset?.();
            modal.classList.add("hidden");
            resetRecaptcha();
        };

        const switchTab = (isLogin) => {
            pending2faChallenge = null;
            $("login-form")?.reset?.();
            $("register-form")?.reset?.();
            $("twofa-form")?.reset?.();
            showAuthStep(isLogin ? "login" : "register");
            updatePasswordMeter();
            resetRecaptcha();
        };

        if ($("open-login-btn")) {
            $("open-login-btn").onclick = () => {
                switchTab(true);
                modal.classList.remove("hidden");
            };
        }
        if ($("open-register-btn")) {
            $("open-register-btn").onclick = () => {
                switchTab(false);
                modal.classList.remove("hidden");
            };
        }
        if ($("logout-btn")) $("logout-btn").onclick = performLogout;
        if ($("profile-logout-btn")) $("profile-logout-btn").onclick = performLogout;
        if ($("tab-login-btn")) $("tab-login-btn").onclick = () => switchTab(true);
        if ($("tab-register-btn")) $("tab-register-btn").onclick = () => switchTab(false);
        if ($("auth-close-btn")) $("auth-close-btn").onclick = closeModal;
        if ($("login-cancel-btn")) $("login-cancel-btn").onclick = closeModal;
        if ($("register-cancel-btn")) $("register-cancel-btn").onclick = closeModal;
        if ($("twofa-cancel-btn")) $("twofa-cancel-btn").onclick = closeModal;
        if ($("twofa-back-btn")) {
            $("twofa-back-btn").onclick = () => {
                pending2faChallenge = null;
                $("twofa-form")?.reset?.();
                showAuthStep("login");
            };
        }

        if ($("twofa-code")) {
            const otpInput = $("twofa-code");

            otpInput.addEventListener("beforeinput", (e) => {
                if (e.data && /\D/.test(e.data)) {
                    e.preventDefault();
                }
            });

            otpInput.addEventListener("paste", (e) => {
                e.preventDefault();
                const pasted = (e.clipboardData || window.clipboardData)?.getData("text") || "";
                const digits = pasted.replace(/\D/g, "");
                if (!digits) return;

                const start = otpInput.selectionStart ?? otpInput.value.length;
                const end = otpInput.selectionEnd ?? otpInput.value.length;
                const combined = (otpInput.value.slice(0, start) + digits + otpInput.value.slice(end))
                    .replace(/\D/g, "")
                    .slice(0, 6);
                otpInput.value = combined;
                const caret = Math.min(start + digits.length, combined.length);
                otpInput.setSelectionRange(caret, caret);
            });

            otpInput.addEventListener("input", () => {
                const cleaned = otpInput.value.replace(/\D/g, "").slice(0, 6);
                if (otpInput.value !== cleaned) {
                    otpInput.value = cleaned;
                }
            });
        }

        if ($("twofa-resend-btn")) {
            $("twofa-resend-btn").onclick = async () => {
                const btn = $("twofa-resend-btn");
                const errEl = $("twofa-error-msg");
                if (!pending2faChallenge) return;
                errEl?.classList.add("hidden");
                btn.disabled = true;
                btn.textContent = "Надсилання...";
                try {
                    const { ok, data } = await core.apiFetch("/api/auth/2fa/resend", {
                        method: "POST",
                        body: JSON.stringify({ challenge_token: pending2faChallenge }),
                    });
                    if (!ok) {
                        errEl.textContent = data.error || data.message || "Не вдалося надіслати код.";
                        errEl.classList.remove("hidden");
                        return;
                    }
                    pending2faChallenge = data.challenge_token;
                    if ($("twofa-info-box") && data.message) {
                        $("twofa-info-box").textContent = data.message;
                    }
                    core.showToast(data.message || "Новий код надіслано.", "success");
                } catch {
                    errEl.textContent = "Не вдалося з'єднатися з сервером.";
                    errEl.classList.remove("hidden");
                } finally {
                    btn.disabled = false;
                    btn.textContent = "Надіслати код повторно";
                }
            };
        }

        if ($("admin-refresh-btn")) $("admin-refresh-btn").onclick = loadAdminPanel;
        if ($("admin-log-filter-btn")) $("admin-log-filter-btn").onclick = loadAdminPanel;
        if ($("admin-log-email-filter")) {
            $("admin-log-email-filter").addEventListener("keydown", (e) => {
                if (e.key === "Enter") {
                    e.preventDefault();
                    loadAdminPanel();
                }
            });
        }

        if ($("reg-password")) $("reg-password").addEventListener("input", updatePasswordMeter);
        if ($("reg-email")) $("reg-email").addEventListener("input", updatePasswordMeter);

        async function handleAuthSubmit(url, payload, errorEl, isLogin) {
            errorEl.classList.add("hidden");
            try {
                const { ok, data } = await core.apiFetch(url, {
                    method: "POST",
                    body: JSON.stringify(payload),
                });
                if (!ok) {
                    const errMsg = data.error || data.message || "Помилка авторизації.";
                    errorEl.textContent = errMsg;
                    errorEl.classList.remove("hidden");
                    if (!isLogin && (payload.captcha_token || errMsg.toLowerCase().includes("recaptcha"))) {
                        resetRecaptcha();
                    }
                    return;
                }

                if (isLogin && data.requires_2fa) {
                    openTwoFactorStep(data.challenge_token, data.message);
                    core.showToast(data.message || "Введіть 6-значний код із пошти.", "warning");
                    return;
                }

                core.setSession(data.user, data.token);
                renderProfile(data.user);
                core.showToast(isLogin ? `Вітаємо, ${data.user.full_name}!` : data.message, "success");
                closeModal();
            } catch {
                errorEl.textContent = "Не вдалося з'єднатися з сервером.";
                errorEl.classList.remove("hidden");
            }
        }

        if ($("login-form")) {
            $("login-form").onsubmit = (e) => {
                e.preventDefault();
                handleAuthSubmit(
                    "/api/auth/login",
                    {
                        email: $("login-email").value.trim(),
                        password: $("login-password").value,
                    },
                    $("login-error-msg"),
                    true
                );
            };
        }

        if ($("twofa-form")) {
            $("twofa-form").onsubmit = async (e) => {
                e.preventDefault();
                const errorEl = $("twofa-error-msg");
                errorEl.classList.add("hidden");
                const code = ($("twofa-code")?.value || "").trim();

                try {
                    const { ok, data } = await core.apiFetch("/api/auth/2fa/verify", {
                        method: "POST",
                        body: JSON.stringify({
                            challenge_token: pending2faChallenge,
                            code,
                        }),
                    });
                    if (!ok) {
                        errorEl.textContent = data.error || data.message || "Невірний код підтвердження.";
                        errorEl.classList.remove("hidden");
                        return;
                    }
                    core.setSession(data.user, data.token);
                    renderProfile(data.user);
                    core.showToast(data.message || `Вітаємо, ${data.user.full_name}!`, "success");
                    closeModal();
                } catch {
                    errorEl.textContent = "Не вдалося з'єднатися з сервером.";
                    errorEl.classList.remove("hidden");
                }
            };
        }

        if ($("register-form")) {
            $("register-form").onsubmit = (e) => {
                e.preventDefault();
                const captchaToken = getRecaptchaToken();
                handleAuthSubmit(
                    "/api/auth/register",
                    {
                        full_name: $("reg-fullname").value.trim(),
                        email: $("reg-email").value.trim(),
                        password: $("reg-password").value,
                        role: $("reg-role").value,
                        captcha_token: captchaToken,
                    },
                    $("reg-error-msg"),
                    false
                );
            };
        }
    }

    window.SecurityApp = {
        renderProfile,
        loadProfile,
        loadAdminPanel,
        logout: performLogout,
        updatePasswordMeter,
        resetRecaptcha,
    };

    document.addEventListener("DOMContentLoaded", () => {
        initSecurityAuthModal();
        initResetPasswordModal();
        if (window.AppCore?.getAuthToken()) {
            loadProfile();
        }
        handleUrlCallbacks();
    });
})();