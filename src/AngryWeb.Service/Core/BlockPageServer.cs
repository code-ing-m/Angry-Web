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
                    onlineRules = cfg.Rules ?? new List<RuleDefinition>(),
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
    <title>Angry Web 관리자 대시보드</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=NanumSquare+Neo:wght@400;700;800&family=Pretendard:wght@400;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --naver-green: #03C75A;
            --naver-green-pressed: #02A94D;
            --naver-green-tint: #E6F8EE;
            --surface: #FFFFFF;
            --surface-muted: #F5F6F8;
            --border: #E4E8EB;
            --border-strong: #C9CED3;
            --text-primary: #1E1E23;
            --text-secondary: #5F6368;
            --text-tertiary: #8E949A;
            --text-inverse: #FFFFFF;
            --link-blue: #3A5CF0;
            --live-red: #F04438;
            --notice-cream: #FFF6E0;
            --sidebar-width: 250px;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: "NanumSquare Neo", "Pretendard", -apple-system, BlinkMacSystemFont, "Apple SD Gothic Neo", "Malgun Gothic", sans-serif;
            -webkit-font-smoothing: antialiased;
        }

        body {
            background-color: var(--surface-muted);
            color: var(--text-primary);
            min-height: 100vh;
        }

        /* ─── 로그인 뷰 ─── */
        .auth-wrapper {
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 24px;
        }

        .auth-card {
            width: 100%;
            max-width: 440px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 44px 36px;
            text-align: center;
        }

        .auth-badge {
            width: 52px;
            height: 52px;
            border-radius: 12px;
            background: var(--naver-green-tint);
            border: 1px solid #c3edd3;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            color: var(--naver-green);
            margin-bottom: 20px;
        }

        .auth-badge svg {
            width: 28px;
            height: 28px;
        }

        .auth-card h1 {
            font-size: 22px;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 8px;
        }

        .auth-card p {
            font-size: 13px;
            color: var(--text-secondary);
            margin-bottom: 28px;
            line-height: 1.5;
        }

        .auth-input {
            width: 100%;
            padding: 13px 16px;
            border: 1px solid var(--border-strong);
            border-radius: 6px;
            font-size: 14px;
            outline: none;
            margin-bottom: 12px;
            background: var(--surface);
            color: var(--text-primary);
            transition: border-color 0.15s;
        }

        .auth-input:focus {
            border-color: var(--naver-green);
            box-shadow: 0 0 0 1px var(--naver-green);
        }

        .btn-naver-primary {
            width: 100%;
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

        .btn-naver-primary:hover {
            background: var(--naver-green-pressed);
        }

        .auth-error {
            color: var(--live-red);
            font-size: 13px;
            margin-top: 12px;
            min-height: 20px;
        }

        .auth-footer-link {
            font-size: 12px;
            color: var(--text-tertiary);
            margin-top: 18px;
            cursor: pointer;
            text-decoration: underline;
        }

        .recovery-box {
            display: none;
            background: var(--surface-muted);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 18px;
            margin-top: 18px;
            text-align: left;
        }

        .recovery-box label {
            font-size: 12px;
            font-weight: 700;
            color: var(--text-secondary);
            display: block;
            margin-bottom: 6px;
        }

        /* ─── 대시보드 셸 레이아웃 (사이드바 + 메인) ─── */
        .app-shell {
            display: none;
            min-height: 100vh;
        }

        .sidebar {
            position: fixed;
            top: 0;
            left: 0;
            bottom: 0;
            width: var(--sidebar-width);
            background: var(--surface);
            border-right: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            z-index: 100;
        }

        .sidebar-brand {
            padding: 24px 20px 20px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .sidebar-logo {
            width: 36px;
            height: 36px;
            background: var(--naver-green);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 800;
            font-size: 18px;
            flex-shrink: 0;
        }

        .sidebar-title h2 {
            font-size: 16px;
            font-weight: 700;
            color: var(--text-primary);
            line-height: 1.2;
        }

        .sidebar-title span {
            font-size: 11px;
            color: var(--text-tertiary);
        }

        .sidebar-nav {
            flex: 1;
            padding: 16px 12px;
            overflow-y: auto;
        }

        .nav-category {
            font-size: 11px;
            font-weight: 700;
            color: var(--text-tertiary);
            padding: 14px 12px 6px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .nav-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 14px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 700;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.15s;
            margin-bottom: 3px;
            user-select: none;
        }

        .nav-item:hover {
            background: var(--surface-muted);
            color: var(--text-primary);
        }

        .nav-item.active {
            background: var(--naver-green-tint);
            color: var(--naver-green);
        }

        .nav-item svg {
            width: 18px;
            height: 18px;
            stroke-width: 2;
        }

        .sidebar-footer {
            padding: 16px;
            border-top: 1px solid var(--border);
            background: var(--surface);
        }

        .sidebar-power-card {
            background: var(--surface-muted);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 12px 14px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 12px;
        }

        .sidebar-power-info span {
            font-size: 11px;
            color: var(--text-secondary);
            display: block;
        }

        .sidebar-power-info strong {
            font-size: 13px;
            font-weight: 700;
        }

        .main-content {
            margin-left: var(--sidebar-width);
            padding: 36px 44px;
            min-height: 100vh;
            max-width: 1400px;
        }

        .tab-pane {
            display: none;
            animation: fadeIn 0.15s ease-out;
        }

        .tab-pane.active {
            display: block;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(4px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* ─── 페이지 헤더 ─── */
        .page-header {
            margin-bottom: 24px;
            padding-bottom: 18px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: flex-end;
            justify-content: space-between;
        }

        .page-title h2 {
            font-size: 22px;
            font-weight: 700;
            color: var(--text-primary);
        }

        .page-title p {
            font-size: 13px;
            color: var(--text-secondary);
            margin-top: 4px;
            line-height: 1.5;
        }

        /* ─── 초보자 안내 가이드 배너 ─── */
        .guide-box {
            background: var(--notice-cream);
            border: 1px solid #F1E5C6;
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 24px;
            display: flex;
            align-items: flex-start;
            gap: 14px;
            font-size: 13px;
            line-height: 1.6;
            color: #5A471C;
        }

        .guide-box svg {
            width: 20px;
            height: 20px;
            flex-shrink: 0;
            color: #C58A00;
            margin-top: 2px;
        }

        .guide-box strong {
            font-weight: 700;
            color: #3D2D0C;
            display: block;
            margin-bottom: 2px;
        }

        /* ─── 통계 그리드 ─── */
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }

        .stat-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px 22px;
        }

        .stat-card .label {
            font-size: 12px;
            font-weight: 700;
            color: var(--text-secondary);
            margin-bottom: 8px;
        }

        .stat-card .value {
            font-size: 28px;
            font-weight: 700;
            color: var(--text-primary);
            line-height: 1;
        }

        .stat-card .value.green { color: var(--naver-green); }
        .stat-card .value.red { color: var(--live-red); }
        .stat-card .value.blue { color: var(--link-blue); }

        /* ─── 네이버 스타일 카드 ─── */
        .card {
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
            margin-bottom: 18px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border);
        }

        .card-title {
            font-size: 16px;
            font-weight: 700;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .card-subtitle {
            font-size: 13px;
            color: var(--text-secondary);
            margin-top: 4px;
        }

        /* ─── 모드 선택 탭 (Online / Hybrid / Local) ─── */
        .mode-selector {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 14px;
            margin-bottom: 16px;
        }

        .mode-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 16px 18px;
            cursor: pointer;
            transition: all 0.15s;
            position: relative;
        }

        .mode-card:hover {
            border-color: var(--border-strong);
        }

        .mode-card.active {
            border-color: var(--naver-green);
            background: #FAFEFB;
        }

        .mode-card.active::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: var(--naver-green);
            border-radius: 6px 6px 0 0;
        }

        .mode-card-title {
            font-size: 14px;
            font-weight: 700;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 6px;
        }

        .mode-card.active .mode-card-title {
            color: var(--naver-green);
        }

        .mode-card-desc {
            font-size: 12px;
            color: var(--text-secondary);
            line-height: 1.5;
        }

        /* ─── 테이블 스타일 ─── */
        .table-responsive {
            width: 100%;
            overflow-x: auto;
            border: 1px solid var(--border);
            border-radius: 6px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            text-align: left;
            background: var(--surface);
        }

        thead th {
            background: #FAFBFC;
            color: var(--text-secondary);
            font-weight: 700;
            font-size: 12px;
            padding: 12px 14px;
            border-bottom: 1px solid var(--border);
            white-space: nowrap;
        }

        tbody td {
            padding: 12px 14px;
            border-bottom: 1px solid var(--border);
            color: var(--text-primary);
            vertical-align: middle;
        }

        tbody tr:last-child td {
            border-bottom: none;
        }

        tbody tr:hover {
            background: #FAFBFC;
        }

        /* ─── 뱃지 & 태그 ─── */
        .badge {
            display: inline-flex;
            align-items: center;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            line-height: 1.4;
        }

        .badge-blocked {
            background: #FEF3F2;
            color: var(--live-red);
            border: 1px solid #FECDCA;
        }

        .badge-allowed {
            background: var(--naver-green-tint);
            color: var(--naver-green);
            border: 1px solid #D1FADF;
        }

        .badge-embed {
            background: #EEF4FF;
            color: var(--link-blue);
            border: 1px solid #D1E0FF;
        }

        .badge-neutral {
            background: var(--surface-muted);
            color: var(--text-secondary);
            border: 1px solid var(--border);
        }

        /* ─── 토글 스위치 ─── */
        .switch {
            position: relative;
            display: inline-block;
            width: 38px;
            height: 22px;
        }

        .switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }

        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #D1D5DB;
            transition: .2s;
            border-radius: 22px;
        }

        .slider:before {
            position: absolute;
            content: "";
            height: 16px;
            width: 16px;
            left: 3px;
            bottom: 3px;
            background-color: white;
            transition: .2s;
            border-radius: 50%;
        }

        input:checked + .slider {
            background-color: var(--naver-green);
        }

        input:checked + .slider:before {
            transform: translateX(16px);
        }

        /* ─── 버튼 ─── */
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            padding: 9px 16px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 700;
            cursor: pointer;
            border: 1px solid transparent;
            transition: all 0.15s;
        }

        .btn-green {
            background: var(--naver-green);
            color: white;
        }
        .btn-green:hover { background: var(--naver-green-pressed); }

        .btn-red {
            background: var(--live-red);
            color: white;
        }
        .btn-red:hover { background: #D92D20; }

        .btn-outline {
            background: var(--surface);
            border-color: var(--border-strong);
            color: var(--text-primary);
        }
        .btn-outline:hover { background: var(--surface-muted); }

        .btn-sm {
            padding: 6px 12px;
            font-size: 12px;
        }

        .btn-del {
            background: transparent;
            color: var(--live-red);
            border: 1px solid #FDA29B;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 700;
            cursor: pointer;
        }
        .btn-del:hover {
            background: #FEF3F2;
        }

        /* ─── 입력창 ─── */
        .input-text {
            padding: 9px 12px;
            border: 1px solid var(--border-strong);
            border-radius: 6px;
            font-size: 13px;
            color: var(--text-primary);
            outline: none;
            background: var(--surface);
        }
        .input-text:focus {
            border-color: var(--naver-green);
        }

        .form-row {
            display: flex;
            gap: 10px;
            align-items: center;
        }

        /* ─── 태그 목록 (임베드 화이트리스트) ─── */
        .tags-container {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            padding: 12px;
            background: var(--surface-muted);
            border: 1px solid var(--border);
            border-radius: 6px;
            min-height: 48px;
            align-items: center;
        }

        .parent-tag {
            background: var(--surface);
            border: 1px solid var(--border-strong);
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 700;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            color: var(--text-primary);
        }

        .parent-tag .remove-btn {
            color: var(--text-tertiary);
            cursor: pointer;
            font-weight: 800;
        }
        .parent-tag .remove-btn:hover {
            color: var(--live-red);
        }

        /* ─── 토스트 ─── */
        #toast {
            position: fixed;
            bottom: 30px;
            right: 30px;
            background: #1E1E23;
            color: white;
            padding: 12px 20px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 700;
            display: none;
            z-index: 9999;
            box-shadow: 0 4px 16px rgba(0,0,0,0.15);
        }
        #toast.show {
            display: block;
            animation: fadeIn 0.2s ease-out;
        }
    </style>
</head>
<body>

<!-- ══════════════ 1. 로그인 화면 ══════════════ -->
<div class="auth-wrapper" id="authView">
    <div class="auth-card">
        <div class="auth-badge">
            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.2" 
                      d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
            </svg>
        </div>
        <h1>Angry Web 제어 대시보드</h1>
        <p>자녀의 웹 사이트 차단 규칙과 실시간 방문 기록을 안전하게 관리하세요.</p>

        <input class="auth-input" id="authPassword" type="password" placeholder="관리자 마스터 비밀번호 입력" onkeypress="if(event.key==='Enter') doLogin();">
        <button class="btn-naver-primary" onclick="doLogin()">대시보드 로그인</button>
        <div class="auth-error" id="authErr"></div>

        <div class="auth-footer-link" onclick="toggleRecovery()">🔑 비밀번호를 잊으셨나요? (비상 복구)</div>
        <div class="recovery-box" id="recoveryBox">
            <label>비상 복구 키 (기본: ANGRY-SAFE-2026-KEY)</label>
            <input class="auth-input" id="resetKey" type="text" placeholder="비상 복구 키 입력">
            <label>새로 설정할 비밀번호</label>
            <input class="auth-input" id="resetNewPw" type="password" placeholder="새 비밀번호 입력">
            <div style="display:flex; gap:8px;">
                <button class="btn btn-green btn-sm" onclick="doResetPassword()">재설정 완료</button>
                <button class="btn btn-outline btn-sm" onclick="toggleRecovery()">취소</button>
            </div>
            <div id="resetMsg" style="font-size:12px; margin-top:8px; min-height:16px;"></div>
        </div>
    </div>
</div>

<!-- ══════════════ 2. 대시보드 메인 레이아웃 ══════════════ -->
<div class="app-shell" id="appView">
    <!-- 좌측 네비게이션 사이드바 -->
    <aside class="sidebar">
        <div class="sidebar-brand">
            <div class="sidebar-logo">N</div>
            <div class="sidebar-title">
                <h2>Angry Web</h2>
                <span>보안 & 집중 모니터링</span>
            </div>
        </div>

        <nav class="sidebar-nav">
            <div class="nav-category">모니터링</div>
            <div class="nav-item active" onclick="switchTab('home')">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/></svg>
                대시보드 홈
            </div>
            <div class="nav-item" onclick="switchTab('log')">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/></svg>
                방문 사이트 기록
            </div>

            <div class="nav-category">차단 규칙 관리</div>
            <div class="nav-item" onclick="switchTab('rules')">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"/></svg>
                차단 규칙 (블랙리스트)
            </div>
            <div class="nav-item" onclick="switchTab('embed')">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 14l9-5-9-5-9 5 9 5zm0 0l6.16-3.422a12.083 12.083 0 01.665 6.479A11.952 11.952 0 0012 20.055a11.952 11.952 0 00-6.824-2.998 12.078 12.078 0 01.665-6.479L12 14z"/></svg>
                인강 임베드 영상 허용
            </div>

            <div class="nav-category">환경 설정</div>
            <div class="nav-item" onclick="switchTab('sync')">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                원격 GitHub 연동
            </div>
            <div class="nav-item" onclick="switchTab('security')">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                비밀번호 & 보안
            </div>
        </nav>

        <div class="sidebar-footer">
            <div class="sidebar-power-card">
                <div class="sidebar-power-info">
                    <span>전체 필터링 상태</span>
                    <strong id="sidebarPowerText">실행 중 (ON)</strong>
                </div>
                <label class="switch">
                    <input type="checkbox" id="globalPowerSwitch" checked onchange="togglePower()">
                    <span class="slider"></span>
                </label>
            </div>
            <button class="btn btn-outline btn-sm" style="width:100%" onclick="doLogout()">로그아웃</button>
        </div>
    </aside>

    <!-- 우측 메인 콘텐츠 영역 -->
    <main class="main-content">

        <!-- ════ 탭 1: 홈 ════ -->
        <div class="tab-pane active" id="tab-home">
            <div class="page-header">
                <div class="page-title">
                    <h2>대시보드 홈</h2>
                    <p>Angry Web 필터링 상태와 PC 이용 현황을 한눈에 모니터링합니다.</p>
                </div>
                <div>
                    <button class="btn btn-outline btn-sm" onclick="syncNow()">🔄 즉시 원격 동기화</button>
                </div>
            </div>

            <div class="guide-box">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                <div>
                    <strong>처음 오셨나요? 초보자를 위한 30초 안내</strong>
                    Angry Web은 백그라운드 Windows 서비스로 조용히 작동하며 유해·오락 사이트를 원천 차단합니다.<br>
                    • <strong>모드 선택</strong>: 기본값인 <strong>Online 모드</strong>는 공식 추천 블랙리스트를 자동 반영하며, <strong>Hybrid 모드</strong>는 온라인 규칙에 더해 부모님이 직접 특정 사이트의 허용/차단을 덮어쓸 수 있습니다.<br>
                    • <strong>인강 시청</strong>: EBS, 메가스터디 등에서 유튜브 강의를 틀 때 막히지 않도록 '인강 임베드 영상 허용' 메뉴에서 도메인을 관리할 수 있습니다.
                </div>
            </div>

            <div class="stat-grid">
                <div class="stat-card">
                    <div class="label">필터링 엔진</div>
                    <div class="value green" id="statPowerStatus">ON</div>
                </div>
                <div class="stat-card">
                    <div class="label">적용 중인 차단 룰</div>
                    <div class="value" id="statActiveRules">-</div>
                </div>
                <div class="stat-card">
                    <div class="label">차단된 접근 시도</div>
                    <div class="value red" id="statBlockedCount">-</div>
                </div>
                <div class="stat-card">
                    <div class="label">정상 접속 확인</div>
                    <div class="value blue" id="statAllowedCount">-</div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <div>
                        <div class="card-title">차단 규칙 적용 모드</div>
                        <div class="card-subtitle">상황에 맞게 룰 적용 방식을 선택할 수 있습니다.</div>
                    </div>
                </div>

                <div class="mode-selector">
                    <div class="mode-card active" id="homeModeCard-Online" onclick="selectRuleMode('Online')">
                        <div class="mode-card-title">
                            <span>🌐 온라인 모드 (추천)</span>
                            <span class="badge badge-allowed">기본</span>
                        </div>
                        <div class="mode-card-desc">
                            GitHub에서 최신으로 검증된 블랙리스트(게임/쇼츠/웹툰 등)를 자동 동기화하여 적용합니다.
                        </div>
                    </div>

                    <div class="mode-card" id="homeModeCard-Hybrid" onclick="selectRuleMode('Hybrid')">
                        <div class="mode-card-title">
                            <span>⚡ 하이브리드 모드</span>
                            <span class="badge badge-embed">로컬 우선</span>
                        </div>
                        <div class="mode-card-desc">
                            온라인 규칙을 기본으로 쓰되, 로컬에서 특정 룰을 끄면 온라인에서 차단 중이어도 즉시 접속을 허용합니다.
                        </div>
                    </div>

                    <div class="mode-card" id="homeModeCard-Local" onclick="selectRuleMode('Local')">
                        <div class="mode-card-title">
                            <span>💻 로컬 단독 모드</span>
                            <span class="badge badge-neutral">수동</span>
                        </div>
                        <div class="mode-card-desc">
                            원격 동기화를 끄고, 관리자가 아래에서 직접 등록한 로컬 규칙만 적용합니다.
                        </div>
                    </div>
                </div>

                <div style="display:flex; justify-content:flex-end;">
                    <button class="btn btn-green" onclick="saveRulesSettings()">모드 변경 사항 저장</button>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <div>
                        <div class="card-title">최근 방문 사이트 미리보기</div>
                        <div class="card-subtitle">PC에서 최근 요청된 주요 웹 사이트 10건입니다.</div>
                    </div>
                    <button class="btn btn-outline btn-sm" onclick="switchTab('log')">전체 기록 보기 →</button>
                </div>

                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th style="width:160px;">접속 시각</th>
                                <th>도메인 (호스트)</th>
                                <th style="width:120px;">판정 상태</th>
                            </tr>
                        </thead>
                        <tbody id="homeRecentLogTable">
                            <tr><td colspan="3" style="text-align:center; padding:24px; color:var(--text-tertiary);">기록을 불러오는 중...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- ════ 탭 2: 방문 사이트 기록 ════ -->
        <div class="tab-pane" id="tab-log">
            <div class="page-header">
                <div class="page-title">
                    <h2>방문 사이트 기록</h2>
                    <p>자녀가 PC 브라우저로 접속한 모든 웹사이트의 주소와 차단/허용 여부를 관리자만 열람할 수 있습니다.</p>
                </div>
                <div style="display:flex; gap:8px;">
                    <button class="btn btn-outline btn-sm" onclick="loadLogData(1)">새로고침</button>
                    <button class="btn btn-red btn-sm" onclick="clearAllLogs()">기록 전체 비우기</button>
                </div>
            </div>

            <div class="guide-box">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                <div>
                    <strong>방문 기록 활용 팁</strong>
                    • 이미지는 제외하고 실제 사용자가 들어간 웹 페이지 요청만 선별 기록됩니다.<br>
                    • 우측 [차단 룰에 추가] 버튼을 누르면 의심스러운 사이트를 그 자리에서 즉시 차단 블랙리스트에 올릴 수 있습니다.
                </div>
            </div>

            <div class="card" style="padding:16px; margin-bottom:16px;">
                <div class="form-row">
                    <input class="input-text" id="logFilterHost" type="text" placeholder="도메인 검색 (예: naver, youtube)" style="width:260px;">
                    <select class="input-text" id="logFilterType" style="width:160px;">
                        <option value="">모든 접속 기록</option>
                        <option value="true">차단된 사이트만</option>
                        <option value="false">허용된 사이트만</option>
                    </select>
                    <button class="btn btn-green btn-sm" onclick="loadLogData(1)">검색 필터 적용</button>
                </div>
            </div>

            <div class="card" style="padding:0; overflow:hidden;">
                <div class="table-responsive" style="border:none;">
                    <table>
                        <thead>
                            <tr>
                                <th style="width:150px;">접속 일시</th>
                                <th style="width:180px;">도메인 (호스트)</th>
                                <th>전체 URL 주소</th>
                                <th style="width:110px;">결과</th>
                                <th style="width:140px;">매칭된 규칙</th>
                                <th style="width:90px; text-align:center;">관리</th>
                            </tr>
                        </thead>
                        <tbody id="fullLogTable">
                            <tr><td colspan="6" style="text-align:center; padding:30px; color:var(--text-tertiary);">접속 기록을 조회하고 있습니다...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <div style="display:flex; align-items:center; justify-content:center; gap:16px; margin-top:20px;">
                <button class="btn btn-outline btn-sm" id="btnLogPrev" onclick="loadLogData(currentLogPage-1)" disabled>◀ 이전</button>
                <span id="logPageText" style="font-size:13px; font-weight:700; color:var(--text-secondary);">-</span>
                <button class="btn btn-outline btn-sm" id="btnLogNext" onclick="loadLogData(currentLogPage+1)" disabled>다음 ▶</button>
            </div>
        </div>

        <!-- ════ 탭 3: 차단 규칙 (블랙리스트) ════ -->
        <div class="tab-pane" id="tab-rules">
            <div class="page-header">
                <div class="page-title">
                    <h2>차단 규칙 (블랙리스트)</h2>
                    <p>특정 유해/오락 사이트의 접근을 막는 차단 규칙 목록을 관리합니다.</p>
                </div>
                <button class="btn btn-green" onclick="saveRulesSettings()">💾 모든 규칙 변경사항 저장</button>
            </div>

            <div class="guide-box">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                <div>
                    <strong>규칙 패턴 작성 방법</strong><br>
                    • <strong>전체 도메인 차단</strong>: <code>*.tiktok.com/*</code> (앞뒤에 * 기호를 넣으면 서브도메인까지 전부 막힙니다)<br>
                    • <strong>특정 페이지만 차단</strong>: <code>*.youtube.com/shorts/*</code> (유튜브 일반 영상은 놔두고 쇼츠만 막을 때)
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <div>
                        <div class="card-title">내 PC 전용 로컬 규칙 추가</div>
                        <div class="card-subtitle">부모님이 직접 차단하고 싶은 도메인이나 키워드를 추가하세요.</div>
                    </div>
                </div>

                <div class="form-row" style="margin-bottom:16px;">
                    <input class="input-text" id="newRulePattern" type="text" placeholder="차단 패턴 (예: *.roblox.com/*)" style="flex:2;">
                    <input class="input-text" id="newRuleDesc" type="text" placeholder="설명 (예: 로블록스 게임 차단)" style="flex:2;">
                    <button class="btn btn-green" onclick="addLocalRuleItem()">+ 규칙 추가</button>
                </div>

                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th style="width:30%;">차단 패턴</th>
                                <th style="width:40%;">규칙 설명</th>
                                <th style="width:15%; text-align:center;">활성화 여부</th>
                                <th style="width:15%; text-align:center;">삭제</th>
                            </tr>
                        </thead>
                        <tbody id="localRulesTableBody">
                            <tr><td colspan="4" style="text-align:center; padding:24px; color:var(--text-tertiary);">등록된 로컬 규칙이 없습니다. 위 입력창에서 추가해보세요.</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <div>
                        <div class="card-title">GitHub 공식 온라인 규칙 목록 (<span id="onlineRulesHeaderCount">0</span>개)</div>
                        <div class="card-subtitle">원격 저장소에서 자동으로 배포 및 갱신되는 안전 권장 블랙리스트입니다.</div>
                    </div>
                </div>

                <div class="table-responsive" style="max-height: 380px; overflow-y:auto;">
                    <table>
                        <thead>
                            <tr>
                                <th style="width:35%;">차단 패턴</th>
                                <th style="width:50%;">설명</th>
                                <th style="width:15%; text-align:center;">상태</th>
                            </tr>
                        </thead>
                        <tbody id="onlineRulesTableBody">
                            <tr><td colspan="3" style="text-align:center; padding:24px; color:var(--text-tertiary);">온라인 규칙을 조회 중입니다...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- ════ 탭 4: 인강 임베드 영상 허용 ════ -->
        <div class="tab-pane" id="tab-embed">
            <div class="page-header">
                <div class="page-title">
                    <h2>인강 임베드 영상 허용 (화이트리스트)</h2>
                    <p>인터넷 강의 사이트 안에서 유튜브 강의 영상을 틀 때, 차단되지 않고 원활히 재생되도록 부모 사이트를 등록합니다.</p>
                </div>
                <button class="btn btn-green" onclick="saveRulesSettings()">💾 변경사항 저장</button>
            </div>

            <div class="guide-box">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                <div>
                    <strong>인강 임베드 허용 작동 원리</strong><br>
                    EBS, 메가스터디 등의 인강 사이트에서 유튜브에 업로드된 해설 강의를 iframe으로 불러올 때, 브라우저는 원래 페이지 주소(Referer)를 전달합니다.<br>
                    Angry Web은 유튜브 자체를 차단하고 있더라도, 아래 등록된 <strong>공부 사이트 안에서 재생되는 영상은 똑똑하게 인식하여 통과</strong>시킵니다.
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <div>
                        <div class="card-title">등록된 인강 사이트 목록</div>
                        <div class="card-subtitle">이 사이트들 안에서 재생되는 외부 동영상은 차단 대상에서 제외됩니다.</div>
                    </div>
                </div>

                <div class="tags-container" id="embedTagContainer"></div>

                <div class="form-row" style="margin-top:16px;">
                    <input class="input-text" id="newEmbedInput" type="text" placeholder="새 인강 도메인 (예: ebs.co.kr, megastudy.net)" style="width:320px;">
                    <button class="btn btn-green" onclick="addEmbedTagItem()">+ 사이트 추가</button>
                </div>
            </div>
        </div>

        <!-- ════ 탭 5: 원격 동기화 ════ -->
        <div class="tab-pane" id="tab-sync">
            <div class="page-header">
                <div class="page-title">
                    <h2>원격 GitHub 동기화</h2>
                    <p>부모님이 밖에서 스마트폰이나 다른 PC로 GitHub의 rules.json 파일을 수정하면, 집의 PC가 자동으로 최신 룰을 반영합니다.</p>
                </div>
            </div>

            <div class="guide-box">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                <div>
                    <strong>다른 곳(회사, 스마트폰)에서 룰을 원격 제어하는 방법</strong><br>
                    1. 본인의 GitHub에 포크(Fork)하거나 저장소를 만든 후 <code>rules.json</code> 파일을 올려둡니다.<br>
                    2. 아래의 GitHub Rules URL에 해당 raw 링크를 입력하고 저장합니다.<br>
                    3. 회사나 밖에서 깃허브 웹사이트에 들어가 rules.json에 새 사이트를 적어두기만 하면, 집의 아이 PC가 설정된 주기(예: 10분마다)로 스스로 내려받아 적용합니다!
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <div>
                        <div class="card-title">원격 규칙 URL (Raw 주소)</div>
                        <div class="card-subtitle">최신 차단 룰을 받아올 GitHub의 Raw JSON URL입니다.</div>
                    </div>
                </div>

                <div class="form-row" style="margin-bottom:20px;">
                    <input class="input-text" id="syncGithubUrlInput" type="text" style="flex:1;">
                    <button class="btn btn-green" onclick="saveRulesSettings()">URL 저장</button>
                </div>

                <div class="card-header" style="margin-top:24px;">
                    <div>
                        <div class="card-title">자동 갱신 주기</div>
                        <div class="card-subtitle">집 PC가 원격 저장소를 확인하는 주기입니다.</div>
                    </div>
                </div>

                <div class="form-row">
                    <select class="input-text" id="syncIntervalSelect" style="width:200px;">
                        <option value="5">5분마다 동기화</option>
                        <option value="10" selected>10분마다 동기화 (권장)</option>
                        <option value="30">30분마다 동기화</option>
                        <option value="60">1시간마다 동기화</option>
                    </select>
                    <button class="btn btn-green" onclick="saveRulesSettings()">주기 저장</button>
                    <button class="btn btn-outline" onclick="syncNow()" style="margin-left:auto;">지금 즉시 갱신 (Sync Now)</button>
                </div>
            </div>
        </div>

        <!-- ════ 탭 6: 비밀번호 & 보안 ════ -->
        <div class="tab-pane" id="tab-security">
            <div class="page-header">
                <div class="page-title">
                    <h2>비밀번호 & 보안 보호 정책</h2>
                    <p>관리자 비밀번호를 안전하게 변경하고 적용 중인 시스템 방어 설정을 확인합니다.</p>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <div>
                        <div class="card-title">관리자 마스터 비밀번호 변경</div>
                        <div class="card-subtitle">대시보드 접속 및 차단 페이지 일시 해제 시 사용되는 암호입니다.</div>
                    </div>
                </div>

                <div style="max-width:440px;">
                    <div style="margin-bottom:14px;">
                        <label style="font-size:12px; font-weight:700; color:var(--text-secondary); display:block; margin-bottom:6px;">현재 비밀번호</label>
                        <input class="input-text" id="pwCurrent" type="password" placeholder="현재 비밀번호" style="width:100%;">
                    </div>
                    <div style="margin-bottom:14px;">
                        <label style="font-size:12px; font-weight:700; color:var(--text-secondary); display:block; margin-bottom:6px;">새 비밀번호</label>
                        <input class="input-text" id="pwNew" type="password" placeholder="새 비밀번호" style="width:100%;">
                    </div>
                    <div style="margin-bottom:18px;">
                        <label style="font-size:12px; font-weight:700; color:var(--text-secondary); display:block; margin-bottom:6px;">새 비밀번호 확인</label>
                        <input class="input-text" id="pwConfirm" type="password" placeholder="새 비밀번호 다시 입력" style="width:100%;">
                    </div>
                    <button class="btn btn-green" onclick="doChangePassword()">비밀번호 변경 완료</button>
                    <div id="pwChangeMsg" style="font-size:13px; margin-top:10px; min-height:16px;"></div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <div>
                        <div class="card-title">활성화된 시스템 보안 방어 내역</div>
                        <div class="card-subtitle">자녀의 우회 및 임의 종료를 막기 위해 서비스 자체에 적용된 보호 체계입니다.</div>
                    </div>
                </div>

                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th style="width:25%;">보안 기능</th>
                                <th>보호 내용</th>
                                <th style="width:15%; text-align:center;">상태</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td><strong>5회 오류 시 10분 잠금</strong></td>
                                <td>비밀번호를 연속으로 틀릴 시 무차별 대입 공격을 막기 위해 10분간 입력창이 차단됩니다.</td>
                                <td style="text-align:center;"><span class="badge badge-allowed">적용 중</span></td>
                            </tr>
                            <tr>
                                <td><strong>NTFS 폴더 삭제 방지</strong></td>
                                <td>Program Files 설치 폴더를 일반 사용자가 권한 없이 지우거나 파일을 변조하지 못하도록 ACL 잠금합니다.</td>
                                <td style="text-align:center;"><span class="badge badge-allowed">적용 중</span></td>
                            </tr>
                            <tr>
                                <td><strong>서비스 강제 중지 차단</strong></td>
                                <td>작업 관리자나 서비스 제어판에서 일반 사용자가 서비스를 끄지 못하도록 보호합니다.</td>
                                <td style="text-align:center;"><span class="badge badge-allowed">적용 중</span></td>
                            </tr>
                            <tr>
                                <td><strong>프록시 실시간 감시 (Watchdog)</strong></td>
                                <td>윈도우 네트워크 설정에서 프록시를 끄더라도 5초 이내에 강제로 자동 복구하여 필터링을 유지합니다.</td>
                                <td style="text-align:center;"><span class="badge badge-allowed">적용 중</span></td>
                            </tr>
                            <tr>
                                <td><strong>비상 복구 키 체계</strong></td>
                                <td>비밀번호를 완전히 분실했을 때 관리자 승인 창이나 비상 키를 통해 복원할 수 있습니다.</td>
                                <td style="text-align:center;"><span class="badge badge-allowed">적용 중</span></td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

    </main>
</div>

<div id="toast"></div>

<!-- ══════════════ 3. 프론트엔드 자바스크립트 ══════════════ -->
<script>
    let currentToken = '';
    let currentConfig = null;
    let selectedMode = 'Online';
    let localRules = [];
    let onlineRules = [];
    let allowedEmbedParents = [];
    let isEnabled = true;
    let currentLogPage = 1;

    // ── 로그인 ──
    async function doLogin() {
        const pwInput = document.getElementById('authPassword');
        const errDiv = document.getElementById('authErr');
        errDiv.innerText = '';

        if (!pwInput.value) {
            errDiv.innerText = '비밀번호를 입력해주세요.';
            return;
        }

        try {
            const res = await fetch('/api/dashboard/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: pwInput.value })
            });
            const data = await res.json();
            if (data.success) {
                currentToken = data.token;
                document.getElementById('authView').style.display = 'none';
                document.getElementById('appView').style.display = 'block';
                await loadConfigData();
                await loadHomeRecentLogs();
            } else {
                errDiv.innerText = data.message || '비밀번호가 올바르지 않습니다.';
            }
        } catch {
            errDiv.innerText = '서버와 통신할 수 없습니다.';
        }
    }

    function doLogout() {
        currentToken = '';
        document.getElementById('appView').style.display = 'none';
        document.getElementById('authView').style.display = 'flex';
        document.getElementById('authPassword').value = '';
    }

    function toggleRecovery() {
        const box = document.getElementById('recoveryBox');
        box.style.display = box.style.display === 'block' ? 'none' : 'block';
    }

    async function doResetPassword() {
        const key = document.getElementById('resetKey').value.trim();
        const newPw = document.getElementById('resetNewPw').value.trim();
        const msg = document.getElementById('resetMsg');

        if (!key || !newPw) {
            msg.style.color = 'var(--live-red)';
            msg.innerText = '비상 키와 새 비밀번호를 모두 입력하세요.';
            return;
        }

        try {
            const res = await fetch('/api/dashboard/reset-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ recoveryKey: key, newPassword: newPw })
            });
            const data = await res.json();
            if (data.success) {
                msg.style.color = 'var(--naver-green)';
                msg.innerText = data.message;
                setTimeout(() => {
                    toggleRecovery();
                    document.getElementById('authPassword').value = newPw;
                }, 1500);
            } else {
                msg.style.color = 'var(--live-red)';
                msg.innerText = data.message || '재설정 실패';
            }
        } catch {
            msg.style.color = 'var(--live-red)';
            msg.innerText = '서버 통신 오류';
        }
    }

    // ── 탭 전환 ──
    function switchTab(tabId) {
        document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
        document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));

        const targetPane = document.getElementById('tab-' + tabId);
        if (targetPane) targetPane.classList.add('active');

        // 사이드바 active 표시
        const items = document.querySelectorAll('.nav-item');
        items.forEach(item => {
            if (item.getAttribute('onclick')?.includes(tabId)) {
                item.classList.add('active');
            }
        });

        if (tabId === 'log') {
            loadLogData(1);
        } else if (tabId === 'home') {
            loadHomeRecentLogs();
        }
    }

    // ── 설정 데이터 로드 ──
    async function loadConfigData() {
        try {
            const res = await fetch('/api/dashboard/config', {
                headers: { 'X-Dashboard-Token': currentToken }
            });
            const data = await res.json();
            currentConfig = data;

            selectedMode = data.ruleMode || 'Online';
            localRules = data.localRules || [];
            onlineRules = data.onlineRules || [];
            allowedEmbedParents = data.allowedEmbedParents || [];
            isEnabled = data.isEnabled !== false;

            // 홈 통계
            document.getElementById('statPowerStatus').innerText = isEnabled ? 'ON' : 'OFF';
            document.getElementById('statPowerStatus').className = 'value ' + (isEnabled ? 'green' : 'red');
            document.getElementById('statActiveRules').innerText = (data.activeRulesCount ?? 0) + '개';

            // 사이드바 토글
            document.getElementById('globalPowerSwitch').checked = isEnabled;
            document.getElementById('sidebarPowerText').innerText = isEnabled ? '실행 중 (ON)' : '일시정지 (OFF)';

            // 원격 설정 입력창
            if (data.gitHubRulesUrl) {
                document.getElementById('syncGithubUrlInput').value = data.gitHubRulesUrl;
            }
            if (data.syncIntervalMinutes) {
                document.getElementById('syncIntervalSelect').value = data.syncIntervalMinutes;
            }

            selectRuleMode(selectedMode, false);
            renderLocalRulesTable();
            renderOnlineRulesTable();
            renderEmbedTags();
        } catch (e) {
            showToast('설정 데이터를 불러오지 못했습니다.');
        }
    }

    // ── 모드 선택 ──
    function selectRuleMode(mode, triggerSave = false) {
        selectedMode = mode;
        ['Online', 'Hybrid', 'Local'].forEach(m => {
            const card = document.getElementById('homeModeCard-' + m);
            if (card) {
                card.classList.toggle('active', m === mode);
            }
        });
    }

    // ── 전체 ON/OFF 토글 ──
    async function togglePower() {
        isEnabled = document.getElementById('globalPowerSwitch').checked;
        document.getElementById('sidebarPowerText').innerText = isEnabled ? '실행 중 (ON)' : '일시정지 (OFF)';
        document.getElementById('statPowerStatus').innerText = isEnabled ? 'ON' : 'OFF';
        document.getElementById('statPowerStatus').className = 'value ' + (isEnabled ? 'green' : 'red');
        await saveRulesSettings();
    }

    // ── 로컬 규칙 렌더링 ──
    function renderLocalRulesTable() {
        const tbody = document.getElementById('localRulesTableBody');
        tbody.innerHTML = '';

        if (!localRules || localRules.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:24px; color:var(--text-tertiary);">등록된 로컬 규칙이 없습니다. 위 입력창에서 추가해보세요.</td></tr>';
            return;
        }

        localRules.forEach((rule, idx) => {
            const tr = document.createElement('tr');
            const patternText = rule.Pattern || rule.pattern || '';
            const descText = rule.Description || rule.description || '-';
            const isChecked = (rule.Enabled !== undefined) ? rule.Enabled : (rule.enabled !== false);

            tr.innerHTML = `
                <td><strong style="color:var(--text-primary);">${escapeHtml(patternText)}</strong></td>
                <td style="color:var(--text-secondary);">${escapeHtml(descText)}</td>
                <td style="text-align:center;">
                    <label class="switch" style="margin:0 auto;">
                        <input type="checkbox" ${isChecked ? 'checked' : ''} onchange="toggleLocalRule(${idx}, this.checked)">
                        <span class="slider"></span>
                    </label>
                </td>
                <td style="text-align:center;">
                    <button class="btn-del" onclick="deleteLocalRule(${idx})">삭제</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }

    function toggleLocalRule(idx, val) {
        if (localRules[idx]) {
            localRules[idx].Enabled = val;
            localRules[idx].enabled = val;
        }
    }

    function addLocalRuleItem() {
        const patInput = document.getElementById('newRulePattern');
        const descInput = document.getElementById('newRuleDesc');
        const pat = patInput.value.trim();
        const desc = descInput.value.trim();

        if (!pat) {
            showToast('차단 패턴을 입력해주세요.');
            return;
        }

        localRules.push({
            Pattern: pat,
            Description: desc,
            Enabled: true
        });

        patInput.value = '';
        descInput.value = '';
        renderLocalRulesTable();
        showToast('로컬 규칙이 목록에 추가되었습니다. [모든 규칙 변경사항 저장]을 누르면 적용됩니다.');
    }

    function deleteLocalRule(idx) {
        if (confirm('이 규칙을 삭제하시겠습니까?')) {
            localRules.splice(idx, 1);
            renderLocalRulesTable();
        }
    }

    // ── 온라인 룰 렌더링 ──
    function renderOnlineRulesTable() {
        const tbody = document.getElementById('onlineRulesTableBody');
        const headerCount = document.getElementById('onlineRulesHeaderCount');
        tbody.innerHTML = '';

        headerCount.innerText = onlineRules.length;

        if (!onlineRules || onlineRules.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" style="text-align:center; padding:24px; color:var(--text-tertiary);">온라인 규칙이 없습니다. [원격 동기화]를 진행해보세요.</td></tr>';
            return;
        }

        onlineRules.forEach(rule => {
            const tr = document.createElement('tr');
            const pat = rule.Pattern || rule.pattern || '';
            const desc = rule.Description || rule.description || '-';
            tr.innerHTML = `
                <td><strong>${escapeHtml(pat)}</strong></td>
                <td style="color:var(--text-secondary);">${escapeHtml(desc)}</td>
                <td style="text-align:center;"><span class="badge badge-blocked">차단 중</span></td>
            `;
            tbody.appendChild(tr);
        });
    }

    // ── 인강 임베드 태그 ──
    function renderEmbedTags() {
        const container = document.getElementById('embedTagContainer');
        container.innerHTML = '';

        if (!allowedEmbedParents || allowedEmbedParents.length === 0) {
            container.innerHTML = '<span style="font-size:12px; color:var(--text-tertiary);">등록된 허용 도메인이 없습니다.</span>';
            return;
        }

        allowedEmbedParents.forEach((dom, idx) => {
            const span = document.createElement('span');
            span.className = 'parent-tag';
            span.innerHTML = `<span>${escapeHtml(dom)}</span><span class="remove-btn" onclick="removeEmbedTag(${idx})">×</span>`;
            container.appendChild(span);
        });
    }

    function addEmbedTagItem() {
        const input = document.getElementById('newEmbedInput');
        const val = input.value.trim().toLowerCase();
        if (!val) {
            showToast('도메인 주소를 입력해주세요.');
            return;
        }

        if (!allowedEmbedParents.includes(val)) {
            allowedEmbedParents.push(val);
            input.value = '';
            renderEmbedTags();
            showToast('허용 도메인이 추가되었습니다. [변경사항 저장]을 눌러주세요.');
        } else {
            showToast('이미 등록된 도메인입니다.');
        }
    }

    function removeEmbedTag(idx) {
        allowedEmbedParents.splice(idx, 1);
        renderEmbedTags();
    }

    // ── 모든 설정 서버에 일괄 저장 ──
    async function saveRulesSettings() {
        const gitHubUrl = document.getElementById('syncGithubUrlInput')?.value?.trim();
        const syncInterval = parseInt(document.getElementById('syncIntervalSelect')?.value || '10');

        try {
            const res = await fetch('/api/dashboard/save-rules', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Dashboard-Token': currentToken
                },
                body: JSON.stringify({
                    isEnabled: isEnabled,
                    ruleMode: selectedMode,
                    localRules: localRules,
                    allowedEmbedParents: allowedEmbedParents,
                    gitHubRulesUrl: gitHubUrl,
                    syncIntervalMinutes: syncInterval
                })
            });
            const data = await res.json();
            if (data.success) {
                showToast('✅ 설정이 안전하게 저장되었으며 즉시 적용되었습니다!');
                await loadConfigData();
            } else {
                showToast('❌ 저장 실패: ' + (data.message || ''));
            }
        } catch {
            showToast('통신 오류로 설정을 저장하지 못했습니다.');
        }
    }

    // ── 즉시 동기화 ──
    async function syncNow() {
        try {
            const res = await fetch('/api/dashboard/sync-now', {
                method: 'POST',
                headers: { 'X-Dashboard-Token': currentToken }
            });
            const data = await res.json();
            showToast('🔄 ' + (data.message || 'GitHub 동기화를 시작했습니다.'));
            setTimeout(loadConfigData, 2000);
        } catch {
            showToast('동기화 요청 실패');
        }
    }

    // ── 홈 최근 로그 10건 ──
    async function loadHomeRecentLogs() {
        try {
            const res = await fetch('/api/dashboard/visit-log?page=1', {
                headers: { 'X-Dashboard-Token': currentToken }
            });
            const data = await res.json();
            const tbody = document.getElementById('homeRecentLogTable');
            tbody.innerHTML = '';

            const list = data.entries || [];
            if (list.length === 0) {
                tbody.innerHTML = '<tr><td colspan="3" style="text-align:center; padding:20px; color:var(--text-tertiary);">아직 접속 기록이 없습니다.</td></tr>';
                return;
            }

            // 카운트 계산
            let blockedCount = 0;
            let allowedCount = 0;
            list.forEach(item => {
                if (item.Blocked || item.blocked) blockedCount++;
                else allowedCount++;
            });
            document.getElementById('statBlockedCount').innerText = blockedCount + '건';
            document.getElementById('statAllowedCount').innerText = allowedCount + '건';

            list.slice(0, 10).forEach(entry => {
                const tr = document.createElement('tr');
                const isBlk = entry.Blocked || entry.blocked;
                const isEmb = entry.EmbedAllowed || entry.embedAllowed;
                const host = entry.Host || entry.host || '-';
                const time = formatTime(entry.Timestamp || entry.timestamp);

                let badgeHtml = '<span class="badge badge-allowed">정상 허용</span>';
                if (isBlk) {
                    badgeHtml = '<span class="badge badge-blocked">차단됨</span>';
                } else if (isEmb) {
                    badgeHtml = '<span class="badge badge-embed">인강 예외 허용</span>';
                }

                tr.innerHTML = `
                    <td style="color:var(--text-secondary); font-size:12px;">${time}</td>
                    <td><strong>${escapeHtml(host)}</strong></td>
                    <td>${badgeHtml}</td>
                `;
                tbody.appendChild(tr);
            });
        } catch {}
    }

    // ── 전체 방문 로그 페이징 조회 ──
    async function loadLogData(page) {
        currentLogPage = page;
        const hostFilter = document.getElementById('logFilterHost')?.value?.trim() || '';
        const typeFilter = document.getElementById('logFilterType')?.value || '';

        let query = `/api/dashboard/visit-log?page=${page}`;
        if (hostFilter) query += '&host=' + encodeURIComponent(hostFilter);
        if (typeFilter) query += '&blocked=' + typeFilter;

        try {
            const res = await fetch(query, {
                headers: { 'X-Dashboard-Token': currentToken }
            });
            const data = await res.json();
            const tbody = document.getElementById('fullLogTable');
            tbody.innerHTML = '';

            const list = data.entries || [];
            if (list.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:30px; color:var(--text-tertiary);">조건에 맞는 접속 기록이 없습니다.</td></tr>';
            } else {
                list.forEach(entry => {
                    const tr = document.createElement('tr');
                    const isBlk = entry.Blocked || entry.blocked;
                    const isEmb = entry.EmbedAllowed || entry.embedAllowed;
                    const host = entry.Host || entry.host || '';
                    const url = entry.Url || entry.url || '';
                    const rule = entry.MatchedRule || entry.matchedRule || '-';
                    const time = formatTime(entry.Timestamp || entry.timestamp);

                    let badgeHtml = '<span class="badge badge-allowed">정상 허용</span>';
                    if (isBlk) {
                        badgeHtml = '<span class="badge badge-blocked">차단됨</span>';
                    } else if (isEmb) {
                        badgeHtml = '<span class="badge badge-embed">인강 예외</span>';
                    }

                    tr.innerHTML = `
                        <td style="font-size:12px; color:var(--text-secondary);">${time}</td>
                        <td><strong>${escapeHtml(host)}</strong></td>
                        <td style="font-size:12px; color:var(--text-secondary); max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(url)}">${escapeHtml(url)}</td>
                        <td>${badgeHtml}</td>
                        <td style="font-size:12px; color:var(--text-tertiary);">${escapeHtml(rule)}</td>
                        <td style="text-align:center;">
                            ${!isBlk ? `<button class="btn btn-outline btn-sm" style="padding:2px 8px; font-size:11px;" onclick="quickBlockHost('${escapeHtml(host)}')">차단 추가</button>` : '-'}
                        </td>
                    `;
                    tbody.appendChild(tr);
                });
            }

            // 페이저
            const total = data.total || 0;
            const pageSize = data.pageSize || 100;
            const totalPages = Math.max(1, Math.ceil(total / pageSize));

            document.getElementById('logPageText').innerText = `${page} / ${totalPages} 페이지 (총 ${total}건)`;
            document.getElementById('btnLogPrev').disabled = page <= 1;
            document.getElementById('btnLogNext').disabled = page >= totalPages;
        } catch {
            showToast('로그 데이터를 불러오지 못했습니다.');
        }
    }

    function quickBlockHost(host) {
        if (!host) return;
        switchTab('rules');
        document.getElementById('newRulePattern').value = '*.' + host + '/*';
        document.getElementById('newRuleDesc').value = host + ' 사이트 차단';
        showToast(host + ' 주소가 입력창에 자동으로 채워졌습니다. [+ 규칙 추가]를 누르세요.');
    }

    async function clearAllLogs() {
        if (!confirm('정말로 저장된 모든 방문 사이트 기록을 비우시겠습니까?')) return;
        try {
            const res = await fetch('/api/dashboard/clear-log', {
                method: 'POST',
                headers: { 'X-Dashboard-Token': currentToken }
            });
            const data = await res.json();
            if (data.success) {
                showToast('방문 기록이 모두 비워졌습니다.');
                loadLogData(1);
            }
        } catch {
            showToast('기록 삭제 실패');
        }
    }

    // ── 비밀번호 변경 ──
    async function doChangePassword() {
        const cur = document.getElementById('pwCurrent').value;
        const newPw = document.getElementById('pwNew').value;
        const cfm = document.getElementById('pwConfirm').value;
        const msg = document.getElementById('pwChangeMsg');

        if (!cur || !newPw) {
            msg.style.color = 'var(--live-red)';
            msg.innerText = '현재 비밀번호와 새 비밀번호를 모두 입력하세요.';
            return;
        }
        if (newPw !== cfm) {
            msg.style.color = 'var(--live-red)';
            msg.innerText = '새 비밀번호 확인이 일치하지 않습니다.';
            return;
        }

        try {
            const res = await fetch('/api/dashboard/change-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Dashboard-Token': currentToken
                },
                body: JSON.stringify({ currentPassword: cur, newPassword: newPw })
            });
            const data = await res.json();
            if (data.success) {
                msg.style.color = 'var(--naver-green)';
                msg.innerText = data.message;
                document.getElementById('pwCurrent').value = '';
                document.getElementById('pwNew').value = '';
                document.getElementById('pwConfirm').value = '';
            } else {
                msg.style.color = 'var(--live-red)';
                msg.innerText = data.message || '변경 실패';
            }
        } catch {
            msg.style.color = 'var(--live-red)';
            msg.innerText = '서버 통신 오류';
        }
    }

    // ── 유틸 ──
    function formatTime(isoStr) {
        if (!isoStr) return '-';
        try {
            const d = new Date(isoStr);
            const m = String(d.getMonth() + 1).padStart(2, '0');
            const day = String(d.getDate()).padStart(2, '0');
            const hh = String(d.getHours()).padStart(2, '0');
            const mm = String(d.getMinutes()).padStart(2, '0');
            const ss = String(d.getSeconds()).padStart(2, '0');
            return `${m}/${day} ${hh}:${mm}:${ss}`;
        } catch {
            return isoStr;
        }
    }

    function escapeHtml(str) {
        return (str || '').replace(/[&<>"']/g, m => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        })[m]);
    }

    function showToast(msg) {
        const t = document.getElementById('toast');
        t.innerText = msg;
        t.className = 'show';
        setTimeout(() => { t.className = ''; }, 3200);
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
