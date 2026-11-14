using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;

namespace AngryWeb.Service.Core;

public class BlockPageServer
{
    private readonly ILogger<BlockPageServer> _logger;
    private readonly ConfigManager _configManager;
    private readonly TemporaryAccessManager _accessManager;
    private readonly SiteVisitLogger _visitLogger;
    private HttpListener? _listener;
    private CancellationTokenSource? _cts;

    // 대시보드 로그인 세션 토큰 관리 (1시간 유효)
    private readonly ConcurrentDictionary<string, DateTime> _dashboardSessions = new();

    // 비밀번호 시도 횟수 제한 (5회 오류 시 10분 잠금)
    private int _failedAttempts = 0;
    private DateTime _lockoutUntil = DateTime.MinValue;
    private readonly object _lockoutSync = new();

    public BlockPageServer(ILogger<BlockPageServer> logger, ConfigManager configManager, TemporaryAccessManager accessManager, SiteVisitLogger visitLogger)
    {
        _logger = logger;
        _configManager = configManager;
        _accessManager = accessManager;
        _visitLogger = visitLogger;
    }

    public void Start(int port)
    {
        _cts = new CancellationTokenSource();
        _listener = new HttpListener();
        _listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        _listener.Prefixes.Add($"http://localhost:{port}/");

        try
        {
            _listener.Start();
            _logger.LogInformation("BlockPageServer started on port {Port}", port);
            Task.Run(() => ListenLoop(_cts.Token));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start BlockPageServer on port {Port}", port);
        }
    }

    public void Stop()
    {
        _cts?.Cancel();
        try
        {
            _listener?.Stop();
            _listener?.Close();
        }
        catch { }
    }

    private async Task ListenLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener != null && _listener.IsListening)
        {
            try
            {
                var context = await _listener.GetContextAsync();
                _ = Task.Run(() => HandleRequestAsync(context));
            }
            catch when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning("BlockPage listener error: {Message}", ex.Message);
            }
        }
    }

    private async Task HandleRequestAsync(HttpListenerContext ctx)
    {
        var req = ctx.Request;
        var res = ctx.Response;
        var path = req.Url?.AbsolutePath ?? "/";

        // CORS 헤더 추가 (로컬 요청용)
        res.AddHeader("Access-Control-Allow-Origin", "*");
        res.AddHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Dashboard-Token");
        res.AddHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");

        if (req.HttpMethod == "OPTIONS")
        {
            res.StatusCode = 200;
            res.Close();
            return;
        }

        try
        {
            // 1. 임시 해제 API
            if (req.HttpMethod == "POST" && path == "/api/unlock")
            {
                var lockout = CheckLockout();
                if (!lockout.Allowed)
                {
                    res.StatusCode = 429;
                    await WriteResponse(res, JsonSerializer.Serialize(new { success = false, message = lockout.LockoutMessage }), "application/json");
                    return;
                }

                using var reader = new StreamReader(req.InputStream, req.ContentEncoding);
                var body = await reader.ReadToEndAsync();
                var data = JsonSerializer.Deserialize<UnlockRequest>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                if (data != null && IsPasswordValid(data.Password))
                {
                    RecordPasswordAttempt(true);
                    var minutes = data.Minutes > 0 && data.Minutes <= 120 ? data.Minutes : 15;
                    _accessManager.Allow(data.TargetUrl, TimeSpan.FromMinutes(minutes));
                    _logger.LogInformation("Temporarily allowed {Target} for {Mins} mins", data.TargetUrl, minutes);

                    var successJson = JsonSerializer.Serialize(new { success = true, redirect = data.TargetUrl });
                    await WriteResponse(res, successJson, "application/json");
                    return;
                }

                RecordPasswordAttempt(false);
                var postLock = CheckLockout();
                var failMsg = !postLock.Allowed ? postLock.LockoutMessage : "비밀번호가 올바르지 않습니다.";

                res.StatusCode = 401;
                var failJson = JsonSerializer.Serialize(new { success = false, message = failMsg });
                await WriteResponse(res, failJson, "application/json");
                return;
            }

            // 2. 대시보드 로그인 API
            if (req.HttpMethod == "POST" && path == "/api/dashboard/login")
            {
                var lockout = CheckLockout();
                if (!lockout.Allowed)
                {
                    res.StatusCode = 429;
                    await WriteResponse(res, JsonSerializer.Serialize(new { success = false, message = lockout.LockoutMessage }), "application/json");
                    return;
                }

                using var reader = new StreamReader(req.InputStream, req.ContentEncoding);
                var body = await reader.ReadToEndAsync();
                var data = JsonSerializer.Deserialize<LoginRequest>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                if (data != null && IsPasswordValid(data.Password))
                {
                    RecordPasswordAttempt(true);
                    var token = Guid.NewGuid().ToString("N");
                    _dashboardSessions[token] = DateTime.UtcNow.AddHours(2);
                    var loginSuccess = JsonSerializer.Serialize(new { success = true, token });
                    await WriteResponse(res, loginSuccess, "application/json");
                    return;
                }

                RecordPasswordAttempt(false);
                var postLock = CheckLockout();
                var failMsg = !postLock.Allowed ? postLock.LockoutMessage : "마스터 비밀번호가 올바르지 않습니다.";

                res.StatusCode = 401;
                var loginFail = JsonSerializer.Serialize(new { success = false, message = failMsg });
                await WriteResponse(res, loginFail, "application/json");
                return;
            }

            // 2-1. 비상 복구 키로 비밀번호 재설정 API
            if (req.HttpMethod == "POST" && path == "/api/dashboard/reset-password")
            {
                using var reader = new StreamReader(req.InputStream, req.ContentEncoding);
                var body = await reader.ReadToEndAsync();
                var data = JsonSerializer.Deserialize<ResetPasswordRequest>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                if (data == null || string.IsNullOrWhiteSpace(data.RecoveryKey) || string.IsNullOrWhiteSpace(data.NewPassword))
                {
                    res.StatusCode = 400;
                    await WriteResponse(res, JsonSerializer.Serialize(new { success = false, message = "비상 키와 새 비밀번호를 모두 입력해주세요." }), "application/json");
                    return;
                }

                if (_configManager.ResetPasswordWithRecoveryKey(data.RecoveryKey, data.NewPassword))
                {
                    RecordPasswordAttempt(true); // 잠금 해제
                    await WriteResponse(res, JsonSerializer.Serialize(new { success = true, message = "비밀번호가 성공적으로 재설정되었습니다! 새 비밀번호로 로그인해주세요." }), "application/json");
                    return;
                }

                res.StatusCode = 401;
                await WriteResponse(res, JsonSerializer.Serialize(new { success = false, message = "비상 복구 키가 올바르지 않습니다." }), "application/json");
                return;
            }

            // 3. 대시보드 설정 조회 API
            if (req.HttpMethod == "GET" && path == "/api/dashboard/config")
            {
                if (!IsSessionValid(req))
                {
                    res.StatusCode = 401;
                    await WriteResponse(res, JsonSerializer.Serialize(new { success = false, message = "인증이 필요합니다." }), "application/json");
                    return;
                }

                var cfg = _configManager.CurrentConfig;
                var dto = new
                {
                    isEnabled = cfg.IsEnabled,
                    ruleMode = cfg.RuleMode ?? "Online",
                    gitHubRulesUrl = cfg.GitHubRulesUrl,
                    syncIntervalMinutes = cfg.SyncIntervalMinutes,
                    localRules = cfg.LocalRules ?? new List<RuleDefinition>(),
                    allowedEmbedParents = cfg.AllowedEmbedParents ?? new List<string>(),
                    onlineRulesCount = cfg.Rules?.Count ?? 0,
                    activeRulesCount = _configManager.GetActiveRules().Count()
                };

                await WriteResponse(res, JsonSerializer.Serialize(dto), "application/json");
                return;
            }

            // 4. 비밀번호 변경 API
            if (req.HttpMethod == "POST" && path == "/api/dashboard/change-password")
            {
                if (!IsSessionValid(req))
                {
                    res.StatusCode = 401;
                    await WriteResponse(res, JsonSerializer.Serialize(new { success = false, message = "인증이 필요합니다." }), "application/json");
                    return;
                }

                using var reader = new StreamReader(req.InputStream, req.ContentEncoding);
                var body = await reader.ReadToEndAsync();
                var data = JsonSerializer.Deserialize<ChangePasswordRequest>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                if (data == null || string.IsNullOrWhiteSpace(data.NewPassword))
                {
                    res.StatusCode = 400;
                    await WriteResponse(res, JsonSerializer.Serialize(new { success = false, message = "새 비밀번호를 입력해주세요." }), "application/json");
                    return;
                }

                if (_configManager.UpdatePassword(data.CurrentPassword ?? "", data.NewPassword.Trim()))
                {
                    await WriteResponse(res, JsonSerializer.Serialize(new { success = true, message = "비밀번호가 성공적으로 변경되었습니다." }), "application/json");
                    return;
                }

                res.StatusCode = 400;
                await WriteResponse(res, JsonSerializer.Serialize(new { success = false, message = "현재 비밀번호가 일치하지 않습니다." }), "application/json");
                return;
            }

            // 5. 룰 설정 저장 API (모드 변경, 로컬 룰 추가/삭제/수정, ON/OFF)
            if (req.HttpMethod == "POST" && path == "/api/dashboard/save-rules")
            {
                if (!IsSessionValid(req))
                {
                    res.StatusCode = 401;
                    await WriteResponse(res, JsonSerializer.Serialize(new { success = false, message = "인증이 필요합니다." }), "application/json");
                    return;
                }

                using var reader = new StreamReader(req.InputStream, req.ContentEncoding);
                var body = await reader.ReadToEndAsync();
                var data = JsonSerializer.Deserialize<SaveRulesRequest>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                if (data != null)
                {
                    var mode = data.RuleMode ?? "Online";
                    var localRules = data.LocalRules ?? new List<RuleDefinition>();
                    _configManager.UpdateRuleSettings(mode, localRules, data.GitHubRulesUrl, data.IsEnabled, data.AllowedEmbedParents, data.SyncIntervalMinutes);

                    await WriteResponse(res, JsonSerializer.Serialize(new { success = true, message = "설정이 즉시 적용되었습니다." }), "application/json");
                    return;
                }

                res.StatusCode = 400;
                await WriteResponse(res, JsonSerializer.Serialize(new { success = false, message = "잘못된 데이터입니다." }), "application/json");
                return;
            }

            // 6. 즉시 깃허브 동기화 트리거 API
            if (req.HttpMethod == "POST" && path == "/api/dashboard/sync-now")
            {
                if (!IsSessionValid(req))
                {
                    res.StatusCode = 401;
                    await WriteResponse(res, JsonSerializer.Serialize(new { success = false, message = "인증이 필요합니다." }), "application/json");
                    return;
                }

                _ = Task.Run(() => _configManager.SyncWithGitHubAsync());
                await WriteResponse(res, JsonSerializer.Serialize(new { success = true, message = "동기화 요청이 시작되었습니다." }), "application/json");
                return;
            }

            // 6-1. 방문 사이트 로그 조회 API
            if (req.HttpMethod == "GET" && path == "/api/dashboard/visit-log")
            {
                if (!IsSessionValid(req))
                {
                    res.StatusCode = 401;
                    await WriteResponse(res, JsonSerializer.Serialize(new { success = false, message = "인증이 필요합니다." }), "application/json");
                    return;
                }

                var pageStr = req.QueryString["page"] ?? "1";
                var filterHost = req.QueryString["host"];
                var filterBlockedStr = req.QueryString["blocked"];
                int.TryParse(pageStr, out int page);
                if (page < 1) page = 1;
                bool? filterBlocked = filterBlockedStr == "true" ? true : filterBlockedStr == "false" ? false : null;

                var logs = _visitLogger.GetFromFile(page, 100, filterHost, filterBlocked);
                var total = _visitLogger.GetTotalCount(filterBlocked);
                var dto = new { entries = logs, total, page, pageSize = 100 };
                await WriteResponse(res, JsonSerializer.Serialize(dto), "application/json");
                return;
            }

            // 6-2. 방문 로그 삭제 API
            if (req.HttpMethod == "POST" && path == "/api/dashboard/clear-log")
            {
                if (!IsSessionValid(req))
                {
                    res.StatusCode = 401;
                    await WriteResponse(res, JsonSerializer.Serialize(new { success = false, message = "인증이 필요합니다." }), "application/json");
                    return;
                }

                _visitLogger.ClearLog();
                await WriteResponse(res, JsonSerializer.Serialize(new { success = true, message = "로그가 삭제되었습니다." }), "application/json");
                return;
            }

            // 7. 대시보드 HTML 서빙 (/dashboard 또는 /admin)
            if (path == "/dashboard" || path == "/admin")
            {
                var dashHtml = RenderDashboardHtml();
                await WriteResponse(res, dashHtml, "text/html; charset=utf-8");
                return;
            }

            // 8. 기본: 차단 페이지 HTML
            var target = req.QueryString["target"] ?? "사이트";
            var pattern = req.QueryString["rule"] ?? "";
            var blockHtml = RenderBlockPageHtml(target, pattern);
            await WriteResponse(res, blockHtml, "text/html; charset=utf-8");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling request: {Path}", path);
            res.StatusCode = 500;
            res.Close();
        }
    }

    private (bool Allowed, string? LockoutMessage) CheckLockout()
    {
        lock (_lockoutSync)
        {
            if (DateTime.UtcNow < _lockoutUntil)
            {
                var remaining = _lockoutUntil - DateTime.UtcNow;
                var mins = Math.Ceiling(remaining.TotalMinutes);
                return (false, $"비밀번호를 5회 연속 틀려 보안 잠금되었습니다. {mins}분 후에 다시 시도해주세요.");
            }
            return (true, null);
        }
    }

    private void RecordPasswordAttempt(bool success)
    {
        lock (_lockoutSync)
        {
            if (success)
            {
                _failedAttempts = 0;
                _lockoutUntil = DateTime.MinValue;
            }
            else
            {
                _failedAttempts++;
                if (_failedAttempts >= 5)
                {
                    _lockoutUntil = DateTime.UtcNow.AddMinutes(10);
                    _logger.LogWarning("Security Lockout triggered: 5 consecutive failed attempts. Locked for 10 minutes.");
                }
            }
        }
    }

    private bool IsPasswordValid(string? password)
    {
        if (string.IsNullOrEmpty(password))
            return false;

        var master = _configManager.CurrentConfig.MasterPasswordHash;
        return PasswordHelper.VerifyPassword(master, password);
    }

    private bool IsSessionValid(HttpListenerRequest req)
    {
        var token = req.Headers["X-Dashboard-Token"] ?? req.QueryString["token"];
        if (string.IsNullOrWhiteSpace(token))
            return false;

        if (_dashboardSessions.TryGetValue(token, out var expiry))
        {
            if (DateTime.UtcNow < expiry)
            {
                // 세션 유효 연장
                _dashboardSessions[token] = DateTime.UtcNow.AddHours(2);
                return true;
            }
            _dashboardSessions.TryRemove(token, out _);
        }
        return false;
    }

    private static async Task WriteResponse(HttpListenerResponse res, string content, string contentType)
    {
        var bytes = Encoding.UTF8.GetBytes(content);
        res.ContentType = contentType;
        res.ContentLength64 = bytes.Length;
        await res.OutputStream.WriteAsync(bytes);
        res.OutputStream.Close();
    }

    private string RenderBlockPageHtml(string targetUrl, string matchedRule)
    {
        var bp = _configManager.CurrentConfig.BlockPage;
        return $$"""
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{bp.Title}}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=NanumSquare+Neo:wght@400;700;800&family=Pretendard:wght@400;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --surface: #FFFFFF;
            --surface-muted: #F5F6F8;
            --border: #E4E8EB;
            --border-strong: #C9CED3;
            --text-primary: #1E1E23;
            --text-secondary: #5F6368;
            --text-tertiary: #8E949A;
            --text-inverse: #FFFFFF;
            --naver-green: #03C75A;
            --naver-green-pressed: #02A94D;
            --naver-green-tint: #E6F8EE;
            --live-red: #F04438;
            --link-blue: #3A5CF0;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: "NanumSquare Neo", "Pretendard", -apple-system, BlinkMacSystemFont, "Apple SD Gothic Neo", "Malgun Gothic", sans-serif;
        }

        body {
            background-color: var(--surface-muted);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 40px 24px;
        }

        .container {
            width: 100%;
            max-width: 860px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 48px 44px;
            animation: fadeIn 0.25s ease-out;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(8px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .header-section {
            border-bottom: 1px solid var(--border);
            padding-bottom: 28px;
            margin-bottom: 28px;
            display: flex;
            align-items: flex-start;
            gap: 20px;
        }

        .badge-icon {
            width: 48px;
            height: 48px;
            border-radius: 50%;
            background: var(--naver-green-tint);
            border: 1px solid #c3edd3;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--naver-green);
            flex-shrink: 0;
        }

        .badge-icon svg {
            width: 24px;
            height: 24px;
        }

        .header-content h1 {
            font-size: 24px;
            font-weight: 700;
            line-height: 1.35;
            color: var(--text-primary);
            margin-bottom: 8px;
        }

        .header-content p.subheading {
            font-size: 14px;
            color: var(--text-secondary);
            line-height: 1.6;
        }

        .info-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 16px;
            margin-bottom: 28px;
        }

        .url-card {
            background: var(--surface-muted);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 16px 20px;
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 14px;
        }

        .url-label {
            font-size: 12px;
            font-weight: 700;
            color: var(--text-secondary);
            text-transform: uppercase;
            padding: 2px 8px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 3px;
        }

        .url-text {
            color: var(--link-blue);
            font-weight: 700;
            word-break: break-all;
            flex: 1;
        }

        .quote-card {
            background: #FAFBFC;
            border: 1px solid var(--border);
            border-left: 3px solid var(--naver-green);
            border-radius: 0 6px 6px 0;
            padding: 16px 20px;
            font-size: 14px;
            color: var(--text-secondary);
            line-height: 1.6;
        }

        .quote-card span {
            font-weight: 700;
            color: var(--text-primary);
        }

        .bypass-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
        }

        .card-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 16px;
        }

        .card-title {
            font-size: 15px;
            font-weight: 700;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .card-title svg {
            color: var(--naver-green);
        }

        .bypass-inputs {
            display: grid;
            grid-template-columns: 1fr 140px 120px;
            gap: 12px;
            align-items: center;
        }

        input[type="password"] {
            width: 100%;
            height: 48px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 0 16px;
            font-size: 14px;
            color: var(--text-primary);
            outline: none;
            transition: border-color 0.15s;
        }

        input[type="password"]:focus {
            border-color: var(--naver-green);
            box-shadow: 0 0 0 1px var(--naver-green);
        }

        select {
            width: 100%;
            height: 48px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 0 12px;
            font-size: 14px;
            color: var(--text-primary);
            outline: none;
            cursor: pointer;
        }

        select:focus {
            border-color: var(--naver-green);
        }

        button.btn-unlock {
            height: 48px;
            background: var(--naver-green);
            color: var(--text-inverse);
            border: none;
            border-radius: 6px;
            font-size: 15px;
            font-weight: 700;
            cursor: pointer;
            transition: background 0.15s;
        }

        button.btn-unlock:hover {
            background: var(--naver-green-pressed);
        }

        .status-msg {
            margin-top: 12px;
            font-size: 13px;
            min-height: 20px;
        }
        .status-error { color: var(--live-red); font-weight: 700; }
        .status-success { color: var(--naver-green); font-weight: 700; }

        .footer-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-top: 1px solid var(--border);
            padding-top: 20px;
            font-size: 13px;
            color: var(--text-tertiary);
        }

        .footer-bar a {
            color: var(--text-secondary);
            text-decoration: none;
            font-weight: 600;
        }

        .footer-bar a:hover {
            color: var(--naver-green);
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header-section">
            <div class="badge-icon">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                          d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                </svg>
            </div>
            <div class="header-content">
                <h1>{{bp.Heading}}</h1>
                <p class="subheading">{{bp.Message}}</p>
            </div>
        </div>

        <div class="info-grid">
            <div class="url-card">
                <span class="url-label">차단 URL</span>
                <span class="url-text">{{targetUrl}}</span>
            </div>

            <div class="quote-card">
                <span>오늘의 문구: </span> "{{bp.Quote}}"
            </div>
        </div>

        <div class="bypass-card">
            <div class="card-header">
                <div class="card-title">
                    <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                    </svg>
                    임시 허용 해제 (비밀번호 인증)
                </div>
            </div>
            <div class="bypass-inputs">
                <input type="password" id="pwInput" placeholder="관리자 마스터 비밀번호 입력" onkeypress="if(event.key==='Enter') doUnlock();">
                <select id="durationSelect">
                    <option value="5">5분 허용</option>
                    <option value="15" selected>15분 허용</option>
                    <option value="30">30분 허용</option>
                    <option value="60">1시간 허용</option>
                </select>
                <button class="btn-unlock" onclick="doUnlock()">일시 해제</button>
            </div>
            <div class="status-msg" id="statusMsg"></div>
        </div>

        <div class="footer-bar">
            <span>Angry Web Security & Focus Engine</span>
            <a href="/dashboard">관리자 제어 대시보드 바로가기 →</a>
        </div>
    </div>

    <script>
        async function doUnlock() {
            const pw = document.getElementById('pwInput').value;
            const minutes = parseInt(document.getElementById('durationSelect').value);
            const status = document.getElementById('statusMsg');
            const target = "{{targetUrl}}";

            if (!pw) {
                status.className = 'status-msg status-error';
                status.innerText = '마스터 비밀번호를 입력해주세요.';
                return;
            }

            status.className = 'status-msg';
            status.innerText = '비밀번호 검증 중...';

            try {
                const res = await fetch('/api/unlock', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: pw, targetUrl: target, minutes: minutes })
                });

                const data = await res.json();
                if (data.success) {
                    status.className = 'status-msg status-success';
                    status.innerText = '인증되었습니다! 페이지로 이동합니다...';
                    setTimeout(() => {
                        window.location.href = target.startsWith('http') ? target : ('https://' + target);
                    }, 800);
                } else {
                    status.className = 'status-msg status-error';
                    status.innerText = data.message || '비밀번호가 올바르지 않습니다.';
                }
            } catch (err) {
                status.className = 'status-msg status-error';
                status.innerText = '서버와의 통신 오류가 발생했습니다.';
            }
        }
    </script>
</body>
</html>
""";
    }

    private string RenderDashboardHtml()
    {
        return """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Angry Web - 제어 대시보드</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=NanumSquare+Neo:wght@400;700;800&family=Pretendard:wght@400;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --surface: #FFFFFF;
            --surface-muted: #F5F6F8;
            --border: #E4E8EB;
            --text-primary: #1E1E23;
            --text-secondary: #5F6368;
            --text-tertiary: #8E949A;
            --naver-green: #03C75A;
            --naver-green-pressed: #02A94D;
            --naver-green-tint: #E6F8EE;
            --live-red: #F04438;
            --link-blue: #3A5CF0;
            --sidebar-bg: #1A1D21;
            --sidebar-hover: #2A2D33;
            --sidebar-active: #03C75A;
            --sidebar-text: #B0B7C3;
            --sidebar-text-active: #FFFFFF;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: "NanumSquare Neo", "Pretendard", -apple-system, BlinkMacSystemFont, "Apple SD Gothic Neo", "Malgun Gothic", sans-serif; }
        body { background: var(--surface-muted); color: var(--text-primary); min-height: 100vh; display: flex; align-items: center; justify-content: center; }

        /* ─── 로그인 화면 ─── */
        .auth-wrap { width: 100%; max-width: 440px; padding: 40px 24px; }
        .auth-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 44px 36px; text-align: center; }
        .auth-logo { width: 56px; height: 56px; background: var(--naver-green-tint); border-radius: 14px; display: inline-flex; align-items: center; justify-content: center; margin-bottom: 20px; }
        .auth-logo svg { color: var(--naver-green); }
        .auth-card h1 { font-size: 22px; font-weight: 800; margin-bottom: 6px; }
        .auth-card p { font-size: 13px; color: var(--text-secondary); margin-bottom: 28px; }
        .auth-input { width: 100%; padding: 13px 16px; border: 1.5px solid var(--border); border-radius: 8px; font-size: 15px; outline: none; transition: border 0.2s; margin-bottom: 12px; }
        .auth-input:focus { border-color: var(--naver-green); }
        .btn-primary { width: 100%; padding: 13px; background: var(--naver-green); color: white; border: none; border-radius: 8px; font-size: 15px; font-weight: 700; cursor: pointer; transition: background 0.15s; }
        .btn-primary:hover { background: var(--naver-green-pressed); }
        .auth-err { color: var(--live-red); font-size: 13px; margin-top: 10px; min-height: 20px; }
        .recovery-link { font-size: 12px; color: var(--text-tertiary); margin-top: 16px; cursor: pointer; text-decoration: underline; }
        .recovery-box { display: none; background: #FAFBFC; border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-top: 16px; text-align: left; }
        .recovery-box label { font-size: 12px; font-weight: 700; color: var(--text-secondary); display: block; margin-bottom: 4px; }
        .recovery-box input { width: 100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 13px; margin-bottom: 8px; outline: none; }
        .btn-sm { padding: 8px 16px; border: none; border-radius: 6px; font-size: 13px; font-weight: 700; cursor: pointer; }
        .btn-green { background: var(--naver-green); color: white; }
        .btn-red { background: var(--live-red); color: white; }
        .btn-blue { background: var(--link-blue); color: white; }
        .btn-gray { background: #E4E8EB; color: var(--text-primary); }

        /* ─── 대시보드 레이아웃 ─── */
        .app { display: none; width: 100%; min-height: 100vh; }
        .sidebar { position: fixed; left: 0; top: 0; bottom: 0; width: 240px; background: var(--sidebar-bg); display: flex; flex-direction: column; z-index: 100; }
        .sidebar-brand { padding: 24px 20px 20px; border-bottom: 1px solid rgba(255,255,255,0.08); }
        .sidebar-brand .brand-icon { width: 36px; height: 36px; background: var(--naver-green); border-radius: 8px; display: inline-flex; align-items: center; justify-content: center; margin-right: 10px; vertical-align: middle; }
        .sidebar-brand h2 { display: inline; font-size: 16px; font-weight: 800; color: white; vertical-align: middle; }
        .sidebar-brand p { font-size: 11px; color: var(--sidebar-text); margin-top: 8px; }
        .sidebar-nav { flex: 1; padding: 16px 12px; overflow-y: auto; }
        .nav-section { font-size: 10px; font-weight: 700; color: rgba(255,255,255,0.3); letter-spacing: 0.08em; text-transform: uppercase; padding: 0 8px; margin: 20px 0 8px; }
        .nav-item { display: flex; align-items: center; gap: 10px; padding: 10px 12px; border-radius: 8px; cursor: pointer; color: var(--sidebar-text); font-size: 13px; font-weight: 600; transition: all 0.15s; margin-bottom: 2px; user-select: none; }
        .nav-item:hover { background: var(--sidebar-hover); color: white; }
        .nav-item.active { background: rgba(3,199,90,0.15); color: var(--naver-green); }
        .nav-item svg { flex-shrink: 0; opacity: 0.7; }
        .nav-item.active svg { opacity: 1; }
        .sidebar-footer { padding: 16px 12px; border-top: 1px solid rgba(255,255,255,0.08); }
        .power-toggle { display: flex; align-items: center; justify-content: space-between; padding: 10px 12px; background: rgba(255,255,255,0.05); border-radius: 8px; }
        .power-toggle span { font-size: 12px; font-weight: 700; color: white; }
        .toggle-switch { position: relative; width: 40px; height: 22px; }
        .toggle-switch input { opacity: 0; width: 0; height: 0; }
        .toggle-slider { position: absolute; cursor: pointer; inset: 0; background: #444; border-radius: 22px; transition: 0.3s; }
        .toggle-slider:before { position: absolute; content: ""; height: 16px; width: 16px; left: 3px; bottom: 3px; background: white; border-radius: 50%; transition: 0.3s; }
        input:checked + .toggle-slider { background: var(--naver-green); }
        input:checked + .toggle-slider:before { transform: translateX(18px); }
        .main { margin-left: 240px; min-height: 100vh; padding: 32px 36px; }
        .tab-pane { display: none; }
        .tab-pane.active { display: block; }
        .page-header { margin-bottom: 28px; }
        .page-header h2 { font-size: 22px; font-weight: 800; }
        .page-header p { font-size: 13px; color: var(--text-secondary); margin-top: 4px; }

        /* ─── 카드 ─── */
        .card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 24px; margin-bottom: 20px; }
        .card-title { font-size: 14px; font-weight: 700; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
        .card-title svg { color: var(--naver-green); }
        .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 20px; }
        .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 20px; }
        .stat-card .label { font-size: 12px; font-weight: 700; color: var(--text-secondary); margin-bottom: 8px; }
        .stat-card .value { font-size: 28px; font-weight: 800; }
        .stat-card .value.green { color: var(--naver-green); }
        .stat-card .value.red { color: var(--live-red); }
        .stat-card .value.blue { color: var(--link-blue); }

        /* ─── 모드 선택 ─── */
        .mode-tabs { display: flex; gap: 8px; margin-bottom: 16px; }
        .mode-tab { padding: 8px 18px; border-radius: 20px; border: 1.5px solid var(--border); font-size: 13px; font-weight: 700; cursor: pointer; transition: all 0.15s; background: white; color: var(--text-secondary); }
        .mode-tab.active { border-color: var(--naver-green); background: var(--naver-green-tint); color: var(--naver-green); }
        .mode-desc { font-size: 12px; color: var(--text-secondary); padding: 10px 14px; background: #FAFBFC; border-radius: 6px; border: 1px solid var(--border); margin-bottom: 16px; line-height: 1.6; }

        /* ─── 테이블 ─── */
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        thead th { font-size: 11px; font-weight: 700; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em; padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }
        tbody tr:hover { background: #FAFBFC; }
        tbody td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: middle; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
        .badge-green { background: var(--naver-green-tint); color: var(--naver-green); }
        .badge-red { background: #FEF3F2; color: var(--live-red); }
        .badge-blue { background: #EEF2FF; color: var(--link-blue); }
        .badge-gray { background: #F3F4F6; color: var(--text-secondary); }

        /* ─── 입력 행 ─── */
        .input-row { display: flex; gap: 10px; align-items: center; }
        .input-row input, .input-row select { flex: 1; padding: 10px 14px; border: 1px solid var(--border); border-radius: 8px; font-size: 13px; outline: none; transition: border 0.2s; }
        .input-row input:focus { border-color: var(--naver-green); }
        .tag-list { display: flex; flex-wrap: wrap; gap: 8px; min-height: 36px; padding: 4px 0; }
        .tag { background: #F3F4F6; border: 1px solid var(--border); padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 700; display: inline-flex; align-items: center; gap: 6px; }
        .tag .del { cursor: pointer; color: var(--live-red); font-weight: 800; line-height: 1; }

        /* ─── 로그 테이블 ─── */
        .log-filter { display: flex; gap: 10px; align-items: center; margin-bottom: 16px; flex-wrap: wrap; }
        .log-filter input { padding: 8px 14px; border: 1px solid var(--border); border-radius: 8px; font-size: 13px; outline: none; }
        .log-filter select { padding: 8px 14px; border: 1px solid var(--border); border-radius: 8px; font-size: 13px; outline: none; }
        .pager { display: flex; align-items: center; gap: 10px; justify-content: center; margin-top: 16px; font-size: 13px; }
        .pager button { padding: 6px 14px; border: 1px solid var(--border); border-radius: 6px; background: white; cursor: pointer; font-size: 13px; font-weight: 700; }
        .pager button:disabled { opacity: 0.4; cursor: not-allowed; }

        /* ─── 비밀번호 변경 ─── */
        .pw-row { margin-bottom: 14px; }
        .pw-row label { font-size: 12px; font-weight: 700; color: var(--text-secondary); display: block; margin-bottom: 6px; }
        .pw-row input { width: 100%; max-width: 400px; padding: 10px 14px; border: 1px solid var(--border); border-radius: 8px; font-size: 14px; outline: none; }
        .pw-row input:focus { border-color: var(--naver-green); }
        .sync-row { display: flex; align-items: center; gap: 12px; margin-bottom: 14px; }
        .sync-row input { flex: 1; padding: 10px 14px; border: 1px solid var(--border); border-radius: 8px; font-size: 13px; outline: none; }
        .info-box { background: #EFF6FF; border: 1px solid #BFDBFE; border-radius: 8px; padding: 14px 16px; font-size: 13px; color: #1D4ED8; line-height: 1.6; margin-bottom: 16px; }
        .info-box strong { display: block; margin-bottom: 4px; }
        .sep { height: 1px; background: var(--border); margin: 20px 0; }

        /* ─── 알림 토스트 ─── */
        #toast { position: fixed; bottom: 28px; right: 28px; background: #1A1D21; color: white; padding: 14px 20px; border-radius: 10px; font-size: 14px; font-weight: 700; display: none; z-index: 9999; box-shadow: 0 8px 24px rgba(0,0,0,0.2); }
        #toast.show { display: block; animation: slideUp 0.25s ease-out; }
        @keyframes slideUp { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
        .tab-pane.active { animation: fadeIn 0.2s ease-out; }
    </style>
</head>
<body>

<!-- ══════════════ 로그인 화면 ══════════════ -->
<div class="auth-wrap" id="authView">
    <div class="auth-card">
        <div class="auth-logo">
            <svg width="28" height="28" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
            </svg>
        </div>
        <h1>Angry Web 대시보드</h1>
        <p>관리자 마스터 비밀번호로 인증하세요</p>
        <input class="auth-input" id="authPassword" type="password" placeholder="마스터 비밀번호 입력" onkeypress="if(event.key==='Enter') doLogin();">
        <button class="btn-primary" onclick="doLogin()">대시보드 접속</button>
        <div class="auth-err" id="authErr"></div>
        <div class="recovery-link" onclick="toggleRecovery()">🔑 비밀번호를 잊으셨나요? (비상 복구)</div>
        <div class="recovery-box" id="recoveryBox">
            <label>비상 복구 키</label>
            <input id="resetKey" type="text" placeholder="비상 복구 키 입력 (기본: ANGRY-SAFE-2026-KEY)">
            <label>새 비밀번호</label>
            <input id="resetNewPw" type="password" placeholder="새 비밀번호">
            <div style="display:flex;gap:8px;margin-top:4px;">
                <button class="btn-sm btn-green" onclick="doResetPassword()">비밀번호 재설정</button>
                <button class="btn-sm btn-gray" onclick="toggleRecovery()">취소</button>
            </div>
            <div id="resetMsg" style="font-size:12px;margin-top:8px;min-height:16px;"></div>
        </div>
    </div>
</div>

<!-- ══════════════ 대시보드 ══════════════ -->
<div class="app" id="appView">
    <!-- 사이드바 -->
    <aside class="sidebar">
        <div class="sidebar-brand">
            <span class="brand-icon">
                <svg width="20" height="20" fill="none" stroke="white" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                </svg>
            </span>
            <h2>Angry Web</h2>
            <p>집중 & 보안 필터</p>
        </div>
        <nav class="sidebar-nav">
            <div class="nav-section">모니터링</div>
            <div class="nav-item active" onclick="switchTab('home')">
                <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/></svg>
                대시보드 홈
            </div>
            <div class="nav-item" onclick="switchTab('log')">
                <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/></svg>
                방문 사이트 로그
            </div>
            <div class="nav-section">차단 정책</div>
            <div class="nav-item" onclick="switchTab('rules')">
                <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"/></svg>
                차단 룰 관리
            </div>
            <div class="nav-item" onclick="switchTab('embed')">
                <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 14l9-5-9-5-9 5 9 5zm0 0l6.16-3.422a12.083 12.083 0 01.665 6.479A11.952 11.952 0 0012 20.055a11.952 11.952 0 00-6.824-2.998 12.078 12.078 0 01.665-6.479L12 14z"/></svg>
                인강 임베드 허용
            </div>
            <div class="nav-section">시스템</div>
            <div class="nav-item" onclick="switchTab('sync')">
                <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                원격 동기화
            </div>
            <div class="nav-item" onclick="switchTab('security')">
                <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                보안 설정
            </div>
        </nav>
        <div class="sidebar-footer">
            <div class="power-toggle">
                <span id="sidebarPowerLabel">🟢 필터 ON</span>
                <label class="toggle-switch">
                    <input type="checkbox" id="globalToggle" checked onchange="toggleGlobalPower()">
                    <span class="toggle-slider"></span>
                </label>
            </div>
            <div style="margin-top:12px;">
                <button class="btn-sm btn-gray" style="width:100%" onclick="doLogout()">🚪 로그아웃</button>
            </div>
        </div>
    </aside>

    <!-- 메인 콘텐츠 -->
    <main class="main">
        <!-- ── 홈 탭 ── -->
        <div class="tab-pane active" id="tab-home">
            <div class="page-header">
                <h2>📊 대시보드 홈</h2>
                <p>Angry Web 현재 상태와 활동 현황을 한눈에 확인합니다.</p>
            </div>
            <div class="stat-grid">
                <div class="stat-card">
                    <div class="label">📌 현재 상태</div>
                    <div class="value green" id="statStatus">ON</div>
                </div>
                <div class="stat-card">
                    <div class="label">🛡️ 활성 룰 수</div>
                    <div class="value" id="statRules">-</div>
                </div>
                <div class="stat-card">
                    <div class="label">🚫 오늘 차단</div>
                    <div class="value red" id="statBlocked">-</div>
                </div>
                <div class="stat-card">
                    <div class="label">✅ 오늘 허용</div>
                    <div class="value blue" id="statAllowed">-</div>
                </div>
            </div>
            <div class="card">
                <div class="card-title">
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                    현재 적용 모드
                </div>
                <div class="mode-tabs" id="homeModes">
                    <div class="mode-tab" id="homeMode-Online" onclick="quickSetMode('Online')">🌐 Online</div>
                    <div class="mode-tab" id="homeMode-Hybrid" onclick="quickSetMode('Hybrid')">⚡ Hybrid</div>
                    <div class="mode-tab" id="homeMode-Local" onclick="quickSetMode('Local')">💻 Local</div>
                </div>
                <div class="mode-desc" id="homeModeDesc">모드를 선택하세요.</div>
                <div style="display:flex;gap:10px;flex-wrap:wrap;">
                    <button class="btn-sm btn-green" onclick="saveHomeModeOnly()">✔ 모드 저장</button>
                    <button class="btn-sm btn-blue" onclick="syncNow()">🔄 즉시 동기화</button>
                </div>
            </div>
            <div class="card">
                <div class="card-title">🕐 최근 방문 사이트 (최신 10건)</div>
                <table>
                    <thead><tr><th>시각</th><th>호스트</th><th>상태</th></tr></thead>
                    <tbody id="recentLogBody"></tbody>
                </table>
                <div style="margin-top:12px;"><button class="btn-sm btn-gray" onclick="switchTab('log')">전체 로그 보기 →</button></div>
            </div>
        </div>

        <!-- ── 방문 로그 탭 ── -->
        <div class="tab-pane" id="tab-log">
            <div class="page-header">
                <h2>📜 방문 사이트 로그</h2>
                <p>아이가 방문한 모든 사이트를 관리자만 확인할 수 있습니다. (차단/허용 모두 포함)</p>
            </div>
            <div class="log-filter">
                <input id="logFilterHost" type="text" placeholder="🔍 호스트 필터 (예: youtube.com)">
                <select id="logFilterBlocked">
                    <option value="">전체</option>
                    <option value="true">차단된 사이트만</option>
                    <option value="false">허용된 사이트만</option>
                </select>
                <button class="btn-sm btn-blue" onclick="loadLog(1)">검색</button>
                <button class="btn-sm btn-red" onclick="clearLog()" style="margin-left:auto;">🗑 로그 전체 삭제</button>
            </div>
            <div class="card" style="padding:0;overflow:hidden;">
                <table>
                    <thead><tr><th style="width:160px">시각</th><th>호스트</th><th>URL</th><th style="width:90px">상태</th><th>룰</th></tr></thead>
                    <tbody id="logTableBody"></tbody>
                </table>
            </div>
            <div class="pager">
                <button id="logPrevBtn" onclick="loadLog(currentLogPage-1)" disabled>◀ 이전</button>
                <span id="logPageInfo">-</span>
                <button id="logNextBtn" onclick="loadLog(currentLogPage+1)" disabled>다음 ▶</button>
            </div>
        </div>

        <!-- ── 차단 룰 탭 ── -->
        <div class="tab-pane" id="tab-rules">
            <div class="page-header">
                <h2>🛡️ 차단 룰 관리</h2>
                <p>로컬/온라인/하이브리드 모드와 차단 패턴을 관리합니다.</p>
            </div>
            <div class="card">
                <div class="card-title">적용 모드</div>
                <div class="mode-tabs">
                    <div class="mode-tab" id="ruleMode-Online" onclick="setMode('Online')">🌐 Online</div>
                    <div class="mode-tab" id="ruleMode-Hybrid" onclick="setMode('Hybrid')">⚡ Hybrid</div>
                    <div class="mode-tab" id="ruleMode-Local" onclick="setMode('Local')">💻 Local</div>
                </div>
                <div class="mode-desc" id="ruleModeDesc">모드를 선택하세요.</div>
            </div>
            <div class="card">
                <div class="card-title">로컬 차단 룰</div>
                <div class="input-row" style="margin-bottom:12px;">
                    <input id="newPattern" type="text" placeholder="차단 패턴 (예: *.tiktok.com/*)">
                    <input id="newDesc" type="text" placeholder="설명 (선택)">
                    <button class="btn-sm btn-red" onclick="addLocalRule()">+ 추가</button>
                </div>
                <table>
                    <thead><tr><th>패턴</th><th>설명</th><th style="width:60px">활성</th><th style="width:60px">삭제</th></tr></thead>
                    <tbody id="rulesTableBody"></tbody>
                </table>
            </div>
            <div class="card">
                <div class="card-title">온라인 룰 현황</div>
                <p style="font-size:13px;color:var(--text-secondary);">GitHub에서 동기화된 룰: <strong id="onlineRulesCount">-</strong>개</p>
            </div>
            <button class="btn-sm btn-green" onclick="saveAllRules()">💾 전체 저장 및 적용</button>
        </div>

        <!-- ── 인강 임베드 탭 ── -->
        <div class="tab-pane" id="tab-embed">
            <div class="page-header">
                <h2>🎓 인강 임베드 허용</h2>
                <p>허용된 인강 사이트에서 iframe으로 불러오는 유튜브 등 미디어 콘텐츠를 차단에서 제외합니다.</p>
            </div>
            <div class="card">
                <div class="info-box">
                    <strong>💡 작동 원리</strong>
                    EBS, 메가스터디 등의 인강 사이트 안에서 유튜브 강의 영상을 불러올 때, 브라우저는 Referer 헤더에 부모 사이트 주소를 담아 보냅니다.
                    Angry Web이 이 헤더를 감지하여 등록된 허용 도메인 목록에 있으면 차단을 건너뜁니다.
                </div>
                <div class="card-title">허용 인강 도메인 목록</div>
                <div class="tag-list" id="embedParentList"></div>
                <div class="input-row" style="margin-top:14px;">
                    <input id="newEmbedParent" type="text" placeholder="인강 도메인 추가 (예: ebs.co.kr)">
                    <button class="btn-sm btn-green" onclick="addEmbedParent()">+ 추가</button>
                </div>
            </div>
            <button class="btn-sm btn-green" onclick="saveAllRules()">💾 저장 및 적용</button>
        </div>

        <!-- ── 원격 동기화 탭 ── -->
        <div class="tab-pane" id="tab-sync">
            <div class="page-header">
                <h2>🔄 원격 동기화</h2>
                <p>GitHub 저장소에서 차단 룰을 자동으로 가져옵니다. 외부에서 rules.json을 수정하면 집에 있는 PC에 자동 적용됩니다.</p>
            </div>
            <div class="card">
                <div class="info-box">
                    <strong>📱 외부에서 룰 업데이트하는 방법</strong>
                    1. GitHub 저장소(아래 URL)의 rules.json 파일을 수정합니다.<br>
                    2. 아이 PC는 설정된 주기(기본 10분)마다 자동으로 최신 룰을 가져와 즉시 적용합니다.<br>
                    3. 아래 "지금 동기화"를 누르면 즉시 적용할 수 있습니다.
                </div>
                <div class="card-title">GitHub 룰 URL</div>
                <div class="sync-row">
                    <input id="syncUrl" type="text" placeholder="https://raw.githubusercontent.com/...">
                    <button class="btn-sm btn-blue" onclick="saveSyncUrl()">URL 저장</button>
                </div>
                <div class="card-title" style="margin-top:16px;">동기화 주기</div>
                <div class="sync-row">
                    <select id="syncInterval" style="max-width:200px;padding:10px 14px;border:1px solid var(--border);border-radius:8px;font-size:13px;outline:none;">
                        <option value="5">5분마다</option>
                        <option value="10" selected>10분마다</option>
                        <option value="30">30분마다</option>
                        <option value="60">1시간마다</option>
                    </select>
                    <button class="btn-sm btn-green" onclick="saveSyncInterval()">저장</button>
                </div>
                <div style="margin-top:20px;">
                    <button class="btn-sm btn-blue" onclick="syncNow()">🔄 지금 동기화</button>
                </div>
            </div>
        </div>

        <!-- ── 보안 설정 탭 ── -->
        <div class="tab-pane" id="tab-security">
            <div class="page-header">
                <h2>🔒 보안 설정</h2>
                <p>비밀번호 변경 및 보안 정책을 관리합니다.</p>
            </div>
            <div class="card">
                <div class="card-title">비밀번호 변경</div>
                <div class="pw-row"><label>현재 비밀번호</label><input id="curPw" type="password" placeholder="현재 비밀번호 입력"></div>
                <div class="pw-row"><label>새 비밀번호</label><input id="newPw" type="password" placeholder="새 비밀번호 입력"></div>
                <div class="pw-row"><label>새 비밀번호 확인</label><input id="newPwConfirm" type="password" placeholder="새 비밀번호 재입력"></div>
                <button class="btn-sm btn-green" onclick="changePassword()">비밀번호 변경</button>
                <div id="pwMsg" style="font-size:13px;margin-top:10px;min-height:16px;"></div>
            </div>
            <div class="card">
                <div class="card-title">보안 정책 안내</div>
                <div class="info-box">
                    <strong>🔐 적용 중인 보안 정책</strong>
                    • 비밀번호 연속 5회 오류 시 10분간 로그인 잠금<br>
                    • 대시보드 세션 2시간 자동 만료<br>
                    • 비밀번호 SHA-256 해시 저장<br>
                    • 비상 복구 키: ANGRY-SAFE-2026-KEY (관리자만 사용 가능)<br>
                    • 설치 폴더 NTFS ACL 잠금 (일반 사용자 삭제/변조 불가)<br>
                    • Windows Service DACL 보호 (일반 사용자 중지 불가)<br>
                    • 프록시 레지스트리 Watchdog (우회 차단)
                </div>
            </div>
        </div>
    </main>
</div>

<div id="toast"></div>

<script>
    let currentToken = '';
    let currentConfig = null;
    let selectedMode = 'Online';
    let localRules = [];
    let allowedEmbedParents = [];
    let isEnabled = true;
    let currentLogPage = 1;

    // ── 모드 설명 ──
    const modeDescs = {
        Online: '☁️ <strong>Online 모드</strong>: GitHub에서 동기화한 최신 차단 룰만 적용합니다.',
        Hybrid: '⚡ <strong>Hybrid 모드</strong>: 온라인 룰 + 로컬 룰을 병합 적용합니다. 로컬에서 false로 설정한 패턴은 온라인이 true여도 차단 제외됩니다.',
        Local:  '💻 <strong>Local 모드</strong>: GitHub 동기화 없이 직접 추가한 로컬 룰만 적용합니다.'
    };

    // ── 로그인 ──
    async function doLogin() {
        const pw = document.getElementById('authPassword').value;
        const err = document.getElementById('authErr');
        err.innerText = '';
        try {
            const r = await fetch('/api/dashboard/login', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({password:pw}) });
            const d = await r.json();
            if (d.success) {
                currentToken = d.token;
                document.getElementById('authView').style.display = 'none';
                document.getElementById('appView').style.display = 'block';
                await loadConfig();
                await loadRecentLog();
            } else {
                err.innerText = d.message || '비밀번호가 올바르지 않습니다.';
            }
        } catch { err.innerText = '서버 통신 오류가 발생했습니다.'; }
    }

    function doLogout() {
        currentToken = '';
        document.getElementById('appView').style.display = 'none';
        document.getElementById('authView').style.display = 'flex';
        document.getElementById('authPassword').value = '';
    }

    function toggleRecovery() {
        const b = document.getElementById('recoveryBox');
        b.style.display = b.style.display === 'block' ? 'none' : 'block';
    }

    async function doResetPassword() {
        const key = document.getElementById('resetKey').value.trim();
        const newPw = document.getElementById('resetNewPw').value.trim();
        const msg = document.getElementById('resetMsg');
        if (!key || !newPw) { msg.style.color='var(--live-red)'; msg.innerText='비상 키와 새 비밀번호를 모두 입력하세요.'; return; }
        try {
            const r = await fetch('/api/dashboard/reset-password', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({recoveryKey:key, newPassword:newPw}) });
            const d = await r.json();
            if (d.success) {
                msg.style.color = 'var(--naver-green)';
                msg.innerText = d.message;
                setTimeout(() => { toggleRecovery(); document.getElementById('authPassword').value = newPw; }, 1500);
            } else {
                msg.style.color = 'var(--live-red)';
                msg.innerText = d.message || '재설정 실패';
            }
        } catch { msg.style.color='var(--live-red)'; msg.innerText='서버 통신 오류'; }
    }

    // ── 탭 전환 ──
    function switchTab(name) {
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        document.getElementById('tab-' + name).classList.add('active');
        event.currentTarget.classList.add('active');
        if (name === 'log') loadLog(1);
    }

    // ── 설정 로드 ──
    async function loadConfig() {
        try {
            const r = await fetch('/api/dashboard/config', { headers:{'X-Dashboard-Token':currentToken} });
            const d = await r.json();
            currentConfig = d;
            selectedMode = d.ruleMode || 'Online';
            localRules = d.localRules || [];
            allowedEmbedParents = d.allowedEmbedParents || [];
            isEnabled = d.isEnabled !== false;

            // 홈 통계
            document.getElementById('statStatus').innerText = isEnabled ? 'ON' : 'OFF';
            document.getElementById('statStatus').className = 'value ' + (isEnabled ? 'green' : 'red');
            document.getElementById('statRules').innerText = d.activeRulesCount ?? '-';
            document.getElementById('onlineRulesCount').innerText = d.onlineRulesCount ?? '-';

            // URL/interval
            if (d.gitHubRulesUrl) document.getElementById('syncUrl').value = d.gitHubRulesUrl;
            if (d.syncIntervalMinutes) {
                const sel = document.getElementById('syncInterval');
                for (let o of sel.options) { if (o.value == d.syncIntervalMinutes) { o.selected = true; break; } }
            }

            // 토글
            document.getElementById('globalToggle').checked = isEnabled;
            document.getElementById('sidebarPowerLabel').innerText = isEnabled ? '🟢 필터 ON' : '🔴 필터 OFF';

            setMode(selectedMode);
            renderRulesTable();
            renderEmbedParents();
        } catch (e) { toast('설정을 불러오지 못했습니다.'); }
    }

    // ── 모드 선택 ──
    function setMode(m) {
        selectedMode = m;
        ['Online','Hybrid','Local'].forEach(n => {
            const ruleEl = document.getElementById('ruleMode-' + n);
            const homeEl = document.getElementById('homeMode-' + n);
            if (ruleEl) ruleEl.classList.toggle('active', n === m);
            if (homeEl) homeEl.classList.toggle('active', n === m);
        });
        const desc = modeDescs[m] || '';
        const ruleModeDesc = document.getElementById('ruleModeDesc');
        const homeModeDesc = document.getElementById('homeModeDesc');
        if (ruleModeDesc) ruleModeDesc.innerHTML = desc;
        if (homeModeDesc) homeModeDesc.innerHTML = desc;
    }

    function quickSetMode(m) { setMode(m); }

    async function saveHomeModeOnly() {
        await saveAllRules();
    }

    // ── 룰 테이블 ──
    function renderRulesTable() {
        const tbody = document.getElementById('rulesTableBody');
        if (!tbody) return;
        tbody.innerHTML = '';
        if (localRules.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-tertiary);padding:20px">등록된 로컬 룰이 없습니다.</td></tr>';
            return;
        }
        localRules.forEach((rule, idx) => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><code style="font-size:12px">${escapeHtml(rule.pattern)}</code></td>
                <td style="color:var(--text-secondary)">${escapeHtml(rule.description || '-')}</td>
                <td style="text-align:center">
                    <label class="toggle-switch" style="margin:0 auto">
                        <input type="checkbox" ${rule.enabled ? 'checked' : ''} onchange="localRules[${idx}].enabled=this.checked">
                        <span class="toggle-slider"></span>
                    </label>
                </td>
                <td style="text-align:center"><button class="btn-sm btn-red" onclick="deleteRule(${idx})">삭제</button></td>
            `;
            tbody.appendChild(tr);
        });
    }

    function addLocalRule() {
        const pat = document.getElementById('newPattern').value.trim();
        const desc = document.getElementById('newDesc').value.trim();
        if (!pat) { toast('차단 패턴을 입력하세요.'); return; }
        localRules.push({ pattern:pat, description:desc, enabled:true });
        document.getElementById('newPattern').value = '';
        document.getElementById('newDesc').value = '';
        renderRulesTable();
    }

    function deleteRule(idx) {
        if (confirm('이 룰을 삭제하시겠습니까?')) {
            localRules.splice(idx, 1);
            renderRulesTable();
        }
    }

    // ── 임베드 도메인 ──
    function renderEmbedParents() {
        const c = document.getElementById('embedParentList');
        if (!c) return;
        c.innerHTML = '';
        if (allowedEmbedParents.length === 0) {
            c.innerHTML = '<span style="font-size:12px;color:var(--text-tertiary)">등록된 허용 도메인이 없습니다.</span>';
            return;
        }
        allowedEmbedParents.forEach((d, i) => {
            const tag = document.createElement('span');
            tag.className = 'tag';
            tag.innerHTML = `<strong>${escapeHtml(d)}</strong><span class="del" onclick="deleteEmbedParent(${i})">×</span>`;
            c.appendChild(tag);
        });
    }

    function addEmbedParent() {
        const v = document.getElementById('newEmbedParent').value.trim().toLowerCase();
        if (!v) { toast('도메인을 입력하세요.'); return; }
        if (!allowedEmbedParents.includes(v)) {
            allowedEmbedParents.push(v);
            document.getElementById('newEmbedParent').value = '';
            renderEmbedParents();
        }
    }

    function deleteEmbedParent(idx) {
        allowedEmbedParents.splice(idx, 1);
        renderEmbedParents();
    }

    // ── 저장 ──
    async function saveAllRules() {
        try {
            const r = await fetch('/api/dashboard/save-rules', {
                method:'POST',
                headers:{'Content-Type':'application/json','X-Dashboard-Token':currentToken},
                body: JSON.stringify({ isEnabled, ruleMode:selectedMode, localRules, allowedEmbedParents, gitHubRulesUrl: document.getElementById('syncUrl')?.value?.trim() })
            });
            const d = await r.json();
            if (d.success) { toast('✅ 설정이 저장되었습니다!'); await loadConfig(); }
            else toast('❌ 저장 실패: ' + (d.message || ''));
        } catch { toast('저장 중 오류가 발생했습니다.'); }
    }

    async function saveSyncUrl() {
        await saveAllRules();
    }

    async function saveSyncInterval() {
        const v = document.getElementById('syncInterval').value;
        try {
            const r = await fetch('/api/dashboard/save-rules', {
                method:'POST',
                headers:{'Content-Type':'application/json','X-Dashboard-Token':currentToken},
                body: JSON.stringify({ isEnabled, ruleMode:selectedMode, localRules, allowedEmbedParents, syncIntervalMinutes: parseInt(v) })
            });
            const d = await r.json();
            if (d.success) toast('✅ 동기화 주기가 저장되었습니다!');
            else toast('❌ ' + (d.message || ''));
        } catch { toast('저장 중 오류'); }
    }

    async function syncNow() {
        try {
            const r = await fetch('/api/dashboard/sync-now', { method:'POST', headers:{'X-Dashboard-Token':currentToken} });
            const d = await r.json();
            toast('🔄 ' + (d.message || '동기화 요청 완료'));
            setTimeout(() => loadConfig(), 2000);
        } catch { toast('동기화 요청 실패'); }
    }

    // ── 전체 ON/OFF ──
    async function toggleGlobalPower() {
        isEnabled = document.getElementById('globalToggle').checked;
        document.getElementById('sidebarPowerLabel').innerText = isEnabled ? '🟢 필터 ON' : '🔴 필터 OFF';
        await saveAllRules();
    }

    // ── 방문 로그 ──
    async function loadRecentLog() {
        try {
            const r = await fetch('/api/dashboard/visit-log?page=1', { headers:{'X-Dashboard-Token':currentToken} });
            const d = await r.json();
            const tbody = document.getElementById('recentLogBody');
            if (!tbody) return;
            tbody.innerHTML = '';
            const entries = (d.entries || []).slice(0, 10);
            if (entries.length === 0) {
                tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:var(--text-tertiary);padding:16px">아직 기록이 없습니다.</td></tr>';
                return;
            }
            const blockedCount = (d.entries || []).filter(e => e.blocked).length;
            const allowedCount = (d.entries || []).filter(e => !e.blocked).length;
            document.getElementById('statBlocked').innerText = blockedCount;
            document.getElementById('statAllowed').innerText = allowedCount;
            entries.forEach(e => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td style="font-size:12px;color:var(--text-secondary)">${formatTime(e.timestamp)}</td>
                    <td style="font-size:13px;font-weight:700">${escapeHtml(e.host)}</td>
                    <td>${e.blocked ? '<span class="badge badge-red">차단</span>' : (e.embedAllowed ? '<span class="badge badge-blue">임베드허용</span>' : '<span class="badge badge-green">허용</span>')}</td>
                `;
                tbody.appendChild(tr);
            });
        } catch {}
    }

    async function loadLog(page) {
        currentLogPage = page;
        const host = document.getElementById('logFilterHost')?.value?.trim() || '';
        const blocked = document.getElementById('logFilterBlocked')?.value || '';
        let url = `/api/dashboard/visit-log?page=${page}`;
        if (host) url += '&host=' + encodeURIComponent(host);
        if (blocked) url += '&blocked=' + blocked;
        try {
            const r = await fetch(url, { headers:{'X-Dashboard-Token':currentToken} });
            const d = await r.json();
            const tbody = document.getElementById('logTableBody');
            if (!tbody) return;
            tbody.innerHTML = '';
            const entries = d.entries || [];
            if (entries.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-tertiary);padding:20px">기록이 없습니다.</td></tr>';
            } else {
                entries.forEach(e => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td style="font-size:12px;white-space:nowrap">${formatTime(e.timestamp)}</td>
                        <td style="font-weight:700;font-size:13px">${escapeHtml(e.host)}</td>
                        <td style="font-size:12px;color:var(--text-secondary);max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtml(e.url)}">${escapeHtml(e.url)}</td>
                        <td>${e.blocked ? '<span class="badge badge-red">차단</span>' : (e.embedAllowed ? '<span class="badge badge-blue">임베드</span>' : '<span class="badge badge-green">허용</span>')}</td>
                        <td style="font-size:12px;color:var(--text-tertiary)">${escapeHtml(e.matchedRule || '-')}</td>
                    `;
                    tbody.appendChild(tr);
                });
            }
            const total = d.total || 0;
            const pageSize = d.pageSize || 100;
            const totalPages = Math.ceil(total / pageSize);
            document.getElementById('logPageInfo').innerText = `${page} / ${Math.max(1, totalPages)} 페이지 (총 ${total}건)`;
            document.getElementById('logPrevBtn').disabled = page <= 1;
            document.getElementById('logNextBtn').disabled = page >= totalPages;
        } catch { toast('로그를 불러오지 못했습니다.'); }
    }

    async function clearLog() {
        if (!confirm('모든 방문 로그를 삭제하시겠습니까?')) return;
        try {
            const r = await fetch('/api/dashboard/clear-log', { method:'POST', headers:{'X-Dashboard-Token':currentToken} });
            const d = await r.json();
            if (d.success) { toast('🗑 로그가 삭제되었습니다.'); loadLog(1); }
        } catch { toast('삭제 실패'); }
    }

    // ── 비밀번호 변경 ──
    async function changePassword() {
        const curPw = document.getElementById('curPw').value;
        const newPw = document.getElementById('newPw').value;
        const cfm = document.getElementById('newPwConfirm').value;
        const msg = document.getElementById('pwMsg');
        if (!curPw || !newPw) { msg.style.color='var(--live-red)'; msg.innerText='현재 비밀번호와 새 비밀번호를 모두 입력하세요.'; return; }
        if (newPw !== cfm) { msg.style.color='var(--live-red)'; msg.innerText='새 비밀번호가 일치하지 않습니다.'; return; }
        try {
            const r = await fetch('/api/dashboard/change-password', {
                method:'POST',
                headers:{'Content-Type':'application/json','X-Dashboard-Token':currentToken},
                body: JSON.stringify({ currentPassword:curPw, newPassword:newPw })
            });
            const d = await r.json();
            if (d.success) {
                msg.style.color='var(--naver-green)'; msg.innerText=d.message;
                document.getElementById('curPw').value='';
                document.getElementById('newPw').value='';
                document.getElementById('newPwConfirm').value='';
            } else { msg.style.color='var(--live-red)'; msg.innerText=d.message||'변경 실패'; }
        } catch { msg.style.color='var(--live-red)'; msg.innerText='서버 통신 오류'; }
    }

    // ── 유틸 ──
    function formatTime(ts) {
        if (!ts) return '-';
        const d = new Date(ts);
        return `${d.getMonth()+1}/${d.getDate()} ${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}:${String(d.getSeconds()).padStart(2,'0')}`;
    }

    function escapeHtml(str) {
        return (str || '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[m]);
    }

    function toast(msg) {
        const t = document.getElementById('toast');
        t.innerText = msg;
        t.className = 'show';
        setTimeout(() => { t.className = ''; }, 3000);
    }
</script>
</body>
</html>
""";
    }

    private class UnlockRequest
    {
        public string? Password { get; set; }
        public string TargetUrl { get; set; } = string.Empty;
        public int Minutes { get; set; } = 15;
    }

    private class LoginRequest
    {
        public string? Password { get; set; }
    }

    private class ChangePasswordRequest
    {
        public string? CurrentPassword { get; set; }
        public string? NewPassword { get; set; }
    }

    private class SaveRulesRequest
    {
        public bool? IsEnabled { get; set; }
        public string? RuleMode { get; set; }
        public List<RuleDefinition>? LocalRules { get; set; }
        public List<string>? AllowedEmbedParents { get; set; }
        public string? GitHubRulesUrl { get; set; }
        public int? SyncIntervalMinutes { get; set; }
    }

    private class ResetPasswordRequest
    {
        public string? RecoveryKey { get; set; }
        public string? NewPassword { get; set; }
    }
}
