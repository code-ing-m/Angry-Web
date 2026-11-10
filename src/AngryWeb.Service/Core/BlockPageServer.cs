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
    private HttpListener? _listener;
    private CancellationTokenSource? _cts;

    // 대시보드 로그인 세션 토큰 관리 (1시간 유효)
    private readonly ConcurrentDictionary<string, DateTime> _dashboardSessions = new();

    public BlockPageServer(ILogger<BlockPageServer> logger, ConfigManager configManager, TemporaryAccessManager accessManager)
    {
        _logger = logger;
        _configManager = configManager;
        _accessManager = accessManager;
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
                using var reader = new StreamReader(req.InputStream, req.ContentEncoding);
                var body = await reader.ReadToEndAsync();
                var data = JsonSerializer.Deserialize<UnlockRequest>(body);

                if (data != null && IsPasswordValid(data.Password))
                {
                    var minutes = data.Minutes > 0 && data.Minutes <= 120 ? data.Minutes : 15;
                    _accessManager.Allow(data.TargetUrl, TimeSpan.FromMinutes(minutes));
                    _logger.LogInformation("Temporarily allowed {Target} for {Mins} mins", data.TargetUrl, minutes);

                    var successJson = JsonSerializer.Serialize(new { success = true, redirect = data.TargetUrl });
                    await WriteResponse(res, successJson, "application/json");
                    return;
                }

                res.StatusCode = 401;
                var failJson = JsonSerializer.Serialize(new { success = false, message = "비밀번호가 올바르지 않습니다." });
                await WriteResponse(res, failJson, "application/json");
                return;
            }

            // 2. 대시보드 로그인 API
            if (req.HttpMethod == "POST" && path == "/api/dashboard/login")
            {
                using var reader = new StreamReader(req.InputStream, req.ContentEncoding);
                var body = await reader.ReadToEndAsync();
                var data = JsonSerializer.Deserialize<LoginRequest>(body);

                if (data != null && IsPasswordValid(data.Password))
                {
                    var token = Guid.NewGuid().ToString("N");
                    _dashboardSessions[token] = DateTime.UtcNow.AddHours(2);
                    var loginSuccess = JsonSerializer.Serialize(new { success = true, token });
                    await WriteResponse(res, loginSuccess, "application/json");
                    return;
                }

                res.StatusCode = 401;
                var loginFail = JsonSerializer.Serialize(new { success = false, message = "마스터 비밀번호가 올바르지 않습니다." });
                await WriteResponse(res, loginFail, "application/json");
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
                    ruleMode = cfg.RuleMode ?? "Online",
                    gitHubRulesUrl = cfg.GitHubRulesUrl,
                    localRules = cfg.LocalRules ?? new List<RuleDefinition>(),
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
                var data = JsonSerializer.Deserialize<ChangePasswordRequest>(body);

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

            // 5. 룰 설정 저장 API (모드 변경, 로컬 룰 추가/삭제/수정)
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
                    _configManager.UpdateRuleSettings(mode, localRules, data.GitHubRulesUrl);

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

    private bool IsPasswordValid(string? password)
    {
        var master = _configManager.CurrentConfig.MasterPasswordHash;
        return string.Equals(master, password, StringComparison.Ordinal);
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
    <link href="https://fonts.googleapis.com/css2?family=Pretendard:wght@400;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0d1117;
            --card-bg: rgba(22, 27, 34, 0.85);
            --border-color: rgba(248, 81, 73, 0.3);
            --primary-accent: #f85149;
            --text-main: #f0f6fc;
            --text-muted: #8b949e;
            --input-bg: #090d13;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Pretendard', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }

        body {
            background-color: var(--bg-color);
            background-image: 
                radial-gradient(circle at 50% 20%, rgba(248, 81, 73, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 80% 80%, rgba(139, 148, 158, 0.05) 0%, transparent 40%);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }

        .container {
            width: 100%;
            max-width: 580px;
            background: var(--card-bg);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            padding: 44px 36px;
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6), 0 0 30px rgba(248, 81, 73, 0.1);
            text-align: center;
            animation: fadeIn 0.4s ease-out;
            position: relative;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(12px) scale(0.98); }
            to { opacity: 1; transform: translateY(0) scale(1); }
        }

        .icon-badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 72px;
            height: 72px;
            background: rgba(248, 81, 73, 0.12);
            border: 1px solid rgba(248, 81, 73, 0.4);
            border-radius: 50%;
            margin-bottom: 24px;
            color: var(--primary-accent);
            box-shadow: 0 0 25px rgba(248, 81, 73, 0.25);
        }

        .icon-badge svg {
            width: 36px;
            height: 36px;
        }

        h1 {
            font-size: 26px;
            font-weight: 800;
            letter-spacing: -0.5px;
            margin-bottom: 12px;
            color: #fff;
        }

        p.subheading {
            font-size: 15px;
            color: var(--text-muted);
            margin-bottom: 24px;
            line-height: 1.5;
        }

        .url-box {
            background: var(--input-bg);
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 12px 16px;
            font-size: 13px;
            color: #58a6ff;
            word-break: break-all;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }

        .quote-box {
            border-left: 3px solid var(--primary-accent);
            background: rgba(255, 255, 255, 0.02);
            padding: 14px 18px;
            text-align: left;
            border-radius: 0 10px 10px 0;
            margin-bottom: 30px;
            font-size: 14px;
            color: #c9d1d9;
            font-style: italic;
        }

        .bypass-form {
            background: rgba(13, 17, 23, 0.7);
            border: 1px solid #30363d;
            border-radius: 14px;
            padding: 22px;
            text-align: left;
        }

        .form-title {
            font-size: 13px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin-bottom: 14px;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .form-row {
            display: flex;
            gap: 10px;
        }

        input[type="password"] {
            flex: 1;
            background: var(--input-bg);
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 12px 16px;
            font-size: 14px;
            color: var(--text-main);
            outline: none;
            transition: border-color 0.2s, box-shadow 0.2s;
        }

        input[type="password"]:focus {
            border-color: #58a6ff;
            box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.2);
        }

        button.unlock-btn {
            background: #238636;
            color: #fff;
            border: none;
            border-radius: 8px;
            padding: 12px 20px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s, transform 0.1s;
            white-space: nowrap;
        }

        button.unlock-btn:hover {
            background: #2ea043;
        }

        button.unlock-btn:active {
            transform: scale(0.98);
        }

        .time-select {
            margin-top: 12px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 13px;
            color: var(--text-muted);
        }

        select {
            background: var(--input-bg);
            border: 1px solid #30363d;
            color: var(--text-main);
            padding: 6px 10px;
            border-radius: 6px;
            font-size: 13px;
            outline: none;
        }

        .status-msg {
            margin-top: 12px;
            font-size: 13px;
            min-height: 18px;
        }
        .status-error { color: #f85149; }
        .status-success { color: #3fb950; }

        .dashboard-link {
            margin-top: 22px;
            text-align: center;
        }
        .dashboard-link a {
            font-size: 13px;
            color: #8b949e;
            text-decoration: none;
            transition: color 0.2s;
        }
        .dashboard-link a:hover {
            color: #58a6ff;
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon-badge">
            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                      d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
            </svg>
        </div>
        <h1>{{bp.Heading}}</h1>
        <p class="subheading">{{bp.Message}}</p>

        <div class="url-box">
            <strong>차단 대상:</strong> <span>{{targetUrl}}</span>
        </div>

        <div class="quote-box">
            "{{bp.Quote}}"
        </div>

        <div class="bypass-form">
            <div class="form-title">
                <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                </svg>
                임시 허용 해제 (비밀번호 인증)
            </div>
            <div class="form-row">
                <input type="password" id="pwInput" placeholder="비밀번호 입력" onkeypress="if(event.key==='Enter') doUnlock();">
                <button class="unlock-btn" onclick="doUnlock()">일시 해제</button>
            </div>
            <div class="time-select">
                <span>허용 유지 시간:</span>
                <select id="durationSelect">
                    <option value="5">5분</option>
                    <option value="15" selected>15분</option>
                    <option value="30">30분</option>
                    <option value="60">1시간</option>
                </select>
            </div>
            <div class="status-msg" id="statusMsg"></div>
        </div>

        <div class="dashboard-link">
            <a href="/dashboard">⚙️ Angry Web 관리 대시보드 열기</a>
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
                status.innerText = '비밀번호를 입력하세요.';
                return;
            }

            status.className = 'status-msg';
            status.innerText = '인증 중...';

            try {
                const res = await fetch('/api/unlock', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: pw, targetUrl: target, minutes: minutes })
                });

                const data = await res.json();
                if (data.success) {
                    status.className = 'status-msg status-success';
                    status.innerText = '인증 완료! 원래 페이지로 이동합니다...';
                    setTimeout(() => {
                        window.location.href = target.startsWith('http') ? target : ('https://' + target);
                    }, 1000);
                } else {
                    status.className = 'status-msg status-error';
                    status.innerText = data.message || '인증 실패';
                }
            } catch (err) {
                status.className = 'status-msg status-error';
                status.innerText = '서버 통신 오류가 발생했습니다.';
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
    <link href="https://fonts.googleapis.com/css2?family=Pretendard:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0f17;
            --card-bg: rgba(22, 27, 34, 0.95);
            --border-color: #30363d;
            --primary: #f85149;
            --primary-hover: #ff6b63;
            --accent: #58a6ff;
            --success: #2ea043;
            --text-main: #f0f6fc;
            --text-muted: #8b949e;
            --input-bg: #0d1117;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Pretendard', -apple-system, sans-serif;
        }

        body {
            background-color: var(--bg-color);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }

        .auth-container, .dashboard-container {
            width: 100%;
            max-width: 820px;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 18px;
            padding: 36px;
            box-shadow: 0 25px 60px rgba(0, 0, 0, 0.5);
            display: none;
        }

        .auth-container {
            max-width: 440px;
            text-align: center;
        }

        .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 18px;
            margin-bottom: 24px;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .brand-badge {
            width: 40px;
            height: 40px;
            background: rgba(248, 81, 73, 0.15);
            border: 1px solid var(--primary);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--primary);
            font-weight: 800;
            font-size: 18px;
        }

        .brand-title h2 {
            font-size: 18px;
            font-weight: 700;
        }

        .brand-title p {
            font-size: 12px;
            color: var(--text-muted);
        }

        .section {
            background: rgba(13, 17, 23, 0.6);
            border: 1px solid var(--border-color);
            border-radius: 14px;
            padding: 20px;
            margin-bottom: 20px;
        }

        .section-title {
            font-size: 14px;
            font-weight: 700;
            color: var(--text-main);
            margin-bottom: 14px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .mode-selector {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
            margin-top: 10px;
        }

        .mode-card {
            border: 1px solid var(--border-color);
            background: var(--input-bg);
            border-radius: 10px;
            padding: 14px;
            cursor: pointer;
            transition: all 0.2s;
            text-align: center;
        }

        .mode-card:hover {
            border-color: var(--accent);
        }

        .mode-card.active {
            border-color: var(--primary);
            background: rgba(248, 81, 73, 0.12);
        }

        .mode-card h4 {
            font-size: 14px;
            margin-bottom: 4px;
        }

        .mode-card p {
            font-size: 11px;
            color: var(--text-muted);
            line-height: 1.4;
        }

        .input-group {
            display: flex;
            gap: 10px;
            margin-bottom: 12px;
        }

        input[type="text"], input[type="password"] {
            flex: 1;
            background: var(--input-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 10px 14px;
            font-size: 13px;
            color: var(--text-main);
            outline: none;
        }

        input:focus {
            border-color: var(--accent);
        }

        button {
            border: none;
            border-radius: 8px;
            padding: 10px 18px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s;
        }

        button.btn-primary {
            background: var(--primary);
            color: white;
        }
        button.btn-primary:hover { background: var(--primary-hover); }

        button.btn-success {
            background: var(--success);
            color: white;
        }
        button.btn-success:hover { filter: brightness(1.1); }

        button.btn-secondary {
            background: #21262d;
            color: var(--text-main);
            border: 1px solid var(--border-color);
        }
        button.btn-secondary:hover { background: #30363d; }

        .rules-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            margin-top: 10px;
        }

        .rules-table th {
            text-align: left;
            padding: 8px 10px;
            border-bottom: 1px solid var(--border-color);
            color: var(--text-muted);
            font-weight: 600;
        }

        .rules-table td {
            padding: 10px;
            border-bottom: 1px solid rgba(48, 54, 61, 0.4);
        }

        .rule-badge {
            font-family: monospace;
            background: #161b22;
            padding: 3px 8px;
            border-radius: 5px;
            border: 1px solid var(--border-color);
            color: #58a6ff;
        }

        .btn-del {
            background: transparent;
            color: #f85149;
            padding: 4px 8px;
            font-size: 12px;
        }
        .btn-del:hover { background: rgba(248, 81, 73, 0.15); }

        .notice {
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 8px;
        }

        .stats-bar {
            display: flex;
            gap: 20px;
            font-size: 13px;
            color: var(--text-muted);
        }
        .stats-bar strong { color: var(--text-main); }
    </style>
</head>
<body>

    <!-- 1. 로그인 인증 창 -->
    <div class="auth-container" id="authBox" style="display: block;">
        <div style="margin-bottom: 24px;">
            <div style="font-size: 40px; margin-bottom: 10px;">🛡️</div>
            <h2 style="font-size: 20px; margin-bottom: 6px;">Angry Web 대시보드</h2>
            <p style="font-size: 13px; color: var(--text-muted);">관리자 마스터 비밀번호로 인증하세요</p>
        </div>
        <div style="display: flex; flex-direction: column; gap: 12px;">
            <input type="password" id="authPassword" placeholder="마스터 비밀번호 입력" onkeypress="if(event.key==='Enter') doLogin();">
            <button class="btn-primary" onclick="doLogin()">대시보드 접속</button>
            <div id="authMsg" style="font-size: 13px; color: var(--primary); min-height: 18px;"></div>
        </div>
    </div>

    <!-- 2. 메인 대시보드 -->
    <div class="dashboard-container" id="dashBox">
        <div class="header">
            <div class="brand">
                <div class="brand-badge">AW</div>
                <div class="brand-title">
                    <h2>Angry Web 관리 콘솔</h2>
                    <p>방해 사이트 차단 및 로컬/온라인 정책 제어</p>
                </div>
            </div>
            <div style="display: flex; gap: 10px;">
                <button class="btn-secondary" onclick="doLogout()">로그아웃</button>
                <button class="btn-success" onclick="saveAllSettings()">💾 변경사항 즉시 적용</button>
            </div>
        </div>

        <!-- 1. 제재 정책 모드 설정 -->
        <div class="section">
            <div class="section-title">
                <span>🌐 차단 규칙 정책 모드 선택</span>
                <span class="stats-bar" id="statsBar"></span>
            </div>
            <div class="mode-selector">
                <div class="mode-card" id="modeOnline" onclick="setMode('Online')">
                    <h4>온라인 전용 모드</h4>
                    <p>GitHub 중앙 저장소 블랙리스트만 10분마다 자동 동기화하여 차단합니다.</p>
                </div>
                <div class="mode-card" id="modeLocal" onclick="setMode('Local')">
                    <h4>로컬 전용 모드</h4>
                    <p>외부 GitHub 연결을 끄고, 아래에서 직접 등록한 나만의 로컬 룰만 적용합니다.</p>
                </div>
                <div class="mode-card" id="modeHybrid" onclick="setMode('Hybrid')">
                    <h4>하이브리드 모드 (추천)</h4>
                    <p>GitHub 온라인 공통 룰을 기본 적용하고, 내가 추가한 로컬 룰도 함께 차단합니다.</p>
                </div>
            </div>
        </div>

        <!-- 2. 로컬 차단 규칙 관리 -->
        <div class="section">
            <div class="section-title">
                <span>✏️ 로컬 맞춤 차단 규칙 관리</span>
            </div>
            <div class="input-group">
                <input type="text" id="newPattern" placeholder="차단 패턴 (예: *.roblox.com/*, *game*, watch?v=game)">
                <input type="text" id="newDesc" placeholder="설명 (예: 로블록스 게임 차단)" style="max-width: 200px;">
                <button class="btn-primary" onclick="addLocalRule()">+ 룰 추가</button>
            </div>
            <p class="notice">💡 패턴 문법: <code>site.com/</code>(해당주소만), <code>site.com/*</code>(하위모두), <code>*.site.com/*</code>(서브도메인), <code>*키워드*</code>(키워드포함)</p>
            
            <table class="rules-table">
                <thead>
                    <tr>
                        <th style="width: 50px;">활성</th>
                        <th>차단 패턴</th>
                        <th>설명</th>
                        <th style="width: 70px;">관리</th>
                    </tr>
                </thead>
                <tbody id="rulesTableBody">
                    <!-- Dynamic -->
                </tbody>
            </table>
        </div>

        <!-- 3. 마스터 비밀번호 변경 -->
        <div class="section">
            <div class="section-title">
                <span>🔐 관리자 마스터 비밀번호 변경</span>
            </div>
            <div class="input-group">
                <input type="password" id="curPw" placeholder="현재 비밀번호">
                <input type="password" id="newPw" placeholder="새 비밀번호">
                <input type="password" id="newPwConfirm" placeholder="새 비밀번호 확인">
                <button class="btn-secondary" onclick="changePassword()">비밀번호 변경</button>
            </div>
            <div id="pwMsg" style="font-size: 13px; min-height: 18px;"></div>
        </div>
    </div>

    <script>
        let currentToken = sessionStorage.getItem('aw_token') || '';
        let currentConfig = null;
        let selectedMode = 'Online';
        let localRules = [];

        window.onload = () => {
            if (currentToken) {
                loadConfig();
            } else {
                showAuth();
            }
        };

        function showAuth() {
            document.getElementById('authBox').style.display = 'block';
            document.getElementById('dashBox').style.display = 'none';
        }

        function showDash() {
            document.getElementById('authBox').style.display = 'none';
            document.getElementById('dashBox').style.display = 'block';
        }

        async function doLogin() {
            const pw = document.getElementById('authPassword').value;
            const msg = document.getElementById('authMsg');
            msg.innerText = '';

            try {
                const res = await fetch('/api/dashboard/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: pw })
                });
                const data = await res.json();
                if (data.success) {
                    currentToken = data.token;
                    sessionStorage.setItem('aw_token', currentToken);
                    loadConfig();
                } else {
                    msg.innerText = data.message || '인증 실패';
                }
            } catch (err) {
                msg.innerText = '서버 통신 실패';
            }
        }

        function doLogout() {
            sessionStorage.removeItem('aw_token');
            currentToken = '';
            location.reload();
        }

        async function loadConfig() {
            try {
                const res = await fetch('/api/dashboard/config', {
                    headers: { 'X-Dashboard-Token': currentToken }
                });
                if (res.status === 401) {
                    doLogout();
                    return;
                }
                const data = await res.json();
                currentConfig = data;
                selectedMode = data.ruleMode || 'Online';
                localRules = data.localRules || [];

                setMode(selectedMode, false);
                renderRulesTable();
                updateStats(data);
                showDash();
            } catch (err) {
                alert('설정을 불러오는 중 오류가 발생했습니다.');
            }
        }

        function updateStats(data) {
            document.getElementById('statsBar').innerHTML = 
                `온라인 룰: <strong>${data.onlineRulesCount}개</strong> | 로컬 룰: <strong>${localRules.length}개</strong> | 실제 적용: <strong>${data.activeRulesCount}개</strong>`;
        }

        function setMode(mode, dirty = true) {
            selectedMode = mode;
            ['Online', 'Local', 'Hybrid'].forEach(m => {
                const el = document.getElementById('mode' + m);
                if (el) el.classList.toggle('active', m.toLowerCase() === mode.toLowerCase());
            });
        }

        function renderRulesTable() {
            const tbody = document.getElementById('rulesTableBody');
            tbody.innerHTML = '';

            if (localRules.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 20px;">등록된 로컬 룰이 없습니다. 위에서 새로 추가해보세요.</td></tr>';
                return;
            }

            localRules.forEach((rule, idx) => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><input type="checkbox" ${rule.enabled ? 'checked' : ''} onchange="toggleRule(${idx}, this.checked)"></td>
                    <td><span class="rule-badge">${escapeHtml(rule.pattern)}</span></td>
                    <td style="color: var(--text-muted);">${escapeHtml(rule.description || '-')}</td>
                    <td><button class="btn-del" onclick="deleteRule(${idx})">삭제</button></td>
                `;
                tbody.appendChild(tr);
            });
        }

        function addLocalRule() {
            const pat = document.getElementById('newPattern').value.trim();
            const desc = document.getElementById('newDesc').value.trim();
            if (!pat) {
                alert('차단 패턴을 입력하세요.');
                return;
            }

            localRules.push({ pattern: pat, description: desc, enabled: true });
            document.getElementById('newPattern').value = '';
            document.getElementById('newDesc').value = '';
            renderRulesTable();
        }

        function toggleRule(idx, enabled) {
            localRules[idx].enabled = enabled;
        }

        function deleteRule(idx) {
            if (confirm('이 룰을 삭제하시겠습니까?')) {
                localRules.splice(idx, 1);
                renderRulesTable();
            }
        }

        async function saveAllSettings() {
            try {
                const res = await fetch('/api/dashboard/save-rules', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-Dashboard-Token': currentToken
                    },
                    body: JSON.stringify({
                        ruleMode: selectedMode,
                        localRules: localRules
                    })
                });
                const data = await res.json();
                if (data.success) {
                    alert('성공적으로 저장되었습니다! 즉시 새 정책이 적용됩니다.');
                    loadConfig();
                } else {
                    alert(data.message || '저장 실패');
                }
            } catch (err) {
                alert('통신 오류로 저장하지 못했습니다.');
            }
        }

        async function changePassword() {
            const curPw = document.getElementById('curPw').value;
            const newPw = document.getElementById('newPw').value;
            const confirm = document.getElementById('newPwConfirm').value;
            const msg = document.getElementById('pwMsg');

            if (!curPw || !newPw) {
                msg.style.color = 'var(--primary)';
                msg.innerText = '현재 비밀번호와 새 비밀번호를 모두 입력하세요.';
                return;
            }
            if (newPw !== confirm) {
                msg.style.color = 'var(--primary)';
                msg.innerText = '새 비밀번호가 일치하지 않습니다.';
                return;
            }

            try {
                const res = await fetch('/api/dashboard/change-password', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-Dashboard-Token': currentToken
                    },
                    body: JSON.stringify({ currentPassword: curPw, newPassword: newPw })
                });
                const data = await res.json();
                if (data.success) {
                    msg.style.color = 'var(--success)';
                    msg.innerText = data.message;
                    document.getElementById('curPw').value = '';
                    document.getElementById('newPw').value = '';
                    document.getElementById('newPwConfirm').value = '';
                } else {
                    msg.style.color = 'var(--primary)';
                    msg.innerText = data.message || '변경 실패';
                }
            } catch (err) {
                msg.style.color = 'var(--primary)';
                msg.innerText = '서버 통신 오류';
            }
        }

        function escapeHtml(str) {
            return (str || '').replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[m]);
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
        public string? RuleMode { get; set; }
        public List<RuleDefinition>? LocalRules { get; set; }
        public string? GitHubRulesUrl { get; set; }
    }
}
