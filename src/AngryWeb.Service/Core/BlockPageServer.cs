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
                var data = JsonSerializer.Deserialize<UnlockRequest>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

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
                var data = JsonSerializer.Deserialize<LoginRequest>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

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
                    isEnabled = cfg.IsEnabled,
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
                    _configManager.UpdateRuleSettings(mode, localRules, data.GitHubRulesUrl, data.IsEnabled);

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
            --off-gray: #8E949A;
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
            align-items: flex-start;
            justify-content: center;
            padding: 40px 24px;
        }

        /* 1. 로그인 폼 */
        .auth-container {
            width: 100%;
            max-width: 440px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 40px 32px;
            margin-top: 60px;
            text-align: center;
            display: none;
            animation: fadeIn 0.25s ease-out;
        }

        /* 2. 와이드 대시보드 메인 컨테이너 */
        .dashboard-container {
            width: 100%;
            max-width: 1240px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 36px 40px;
            display: none;
            animation: fadeIn 0.25s ease-out;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(6px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* 헤더 영역 */
        .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid var(--border);
            padding-bottom: 24px;
            margin-bottom: 28px;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .brand-badge {
            width: 44px;
            height: 44px;
            border-radius: 8px;
            background: var(--naver-green-tint);
            border: 1px solid #c3edd3;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--naver-green);
            font-weight: 800;
            font-size: 18px;
        }

        .brand-title h2 {
            font-size: 20px;
            font-weight: 700;
            color: var(--text-primary);
            line-height: 1.3;
        }

        .brand-title p {
            font-size: 13px;
            color: var(--text-secondary);
            margin-top: 2px;
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        /* Angry Web 메인 ON / OFF 스위치 배너 */
        .power-card {
            background: #FAFBFC;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 18px 24px;
            margin-bottom: 28px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .power-info {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .power-status-badge {
            font-size: 12px;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 4px;
            text-transform: uppercase;
        }

        .power-status-badge.on {
            background: var(--naver-green-tint);
            color: var(--naver-green);
            border: 1px solid #b7e8cb;
        }

        .power-status-badge.off {
            background: #F0F2F5;
            color: var(--off-gray);
            border: 1px solid var(--border);
        }

        .power-text h3 {
            font-size: 16px;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 4px;
        }

        .power-text p {
            font-size: 13px;
            color: var(--text-secondary);
        }

        /* 토글 스위치 */
        .switch {
            position: relative;
            display: inline-block;
            width: 54px;
            height: 30px;
        }

        .switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }

        .slider {
            position: absolute;
            cursor: pointer;
            top: 0; left: 0; right: 0; bottom: 0;
            background-color: #D3D8DE;
            transition: 0.2s;
            border-radius: 30px;
        }

        .slider:before {
            position: absolute;
            content: "";
            height: 22px;
            width: 22px;
            left: 4px;
            bottom: 4px;
            background-color: white;
            transition: 0.2s;
            border-radius: 50%;
        }

        input:checked + .slider {
            background-color: var(--naver-green);
        }

        input:checked + .slider:before {
            transform: translateX(24px);
        }

        /* 2단 그리드 레이아웃: 메인 설정(좌측 800px) + 보조 정보/비번(우측 나머지) */
        .dashboard-grid {
            display: grid;
            grid-template-columns: 1fr 340px;
            gap: 24px;
        }

        .section {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
        }

        .section-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 18px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--surface-muted);
        }

        .section-title {
            font-size: 16px;
            font-weight: 700;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .stats-bar {
            font-size: 13px;
            color: var(--text-secondary);
        }
        .stats-bar strong {
            color: var(--naver-green);
        }

        /* 모드 셀렉터 카드 (3열) */
        .mode-selector {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
        }

        .mode-card {
            border: 1px solid var(--border);
            background: var(--surface);
            border-radius: 6px;
            padding: 16px 14px;
            cursor: pointer;
            transition: border-color 0.15s, background-color 0.15s;
            position: relative;
        }

        .mode-card:hover {
            border-color: var(--border-strong);
        }

        .mode-card.active {
            border: 2px solid var(--naver-green);
            background: #FAFEFB;
        }

        .mode-card h4 {
            font-size: 14px;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .mode-card.active h4 {
            color: var(--naver-green);
        }

        .mode-card p {
            font-size: 12px;
            color: var(--text-secondary);
            line-height: 1.5;
        }

        .mode-badge {
            font-size: 10px;
            font-weight: 700;
            padding: 1px 6px;
            border-radius: 3px;
            background: var(--naver-green-tint);
            color: var(--naver-green);
        }

        /* 로컬 룰 관리 테이블 및 입력폼 */
        .add-rule-form {
            display: grid;
            grid-template-columns: 1fr 180px 100px;
            gap: 10px;
            margin-bottom: 12px;
        }

        input[type="text"], input[type="password"] {
            width: 100%;
            height: 44px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 0 14px;
            font-size: 13px;
            color: var(--text-primary);
            outline: none;
            transition: border-color 0.15s;
        }

        input:focus {
            border-color: var(--naver-green);
            box-shadow: 0 0 0 1px var(--naver-green);
        }

        button {
            height: 44px;
            border: none;
            border-radius: 6px;
            padding: 0 18px;
            font-size: 14px;
            font-weight: 700;
            cursor: pointer;
            transition: background 0.15s, border-color 0.15s;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
        }

        button.btn-primary {
            background: var(--naver-green);
            color: var(--text-inverse);
        }
        button.btn-primary:hover {
            background: var(--naver-green-pressed);
        }

        button.btn-secondary {
            background: var(--surface);
            color: var(--text-primary);
            border: 1px solid var(--border);
        }
        button.btn-secondary:hover {
            background: var(--surface-muted);
            border-color: var(--border-strong);
        }

        .notice-box {
            background: #FFFBF0;
            border: 1px solid #FFE6A8;
            border-radius: 6px;
            padding: 10px 14px;
            font-size: 12px;
            color: #8A6400;
            line-height: 1.5;
            margin-bottom: 16px;
        }

        .rules-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        .rules-table th {
            text-align: left;
            padding: 10px 12px;
            background: var(--surface-muted);
            border-top: 1px solid var(--border);
            border-bottom: 1px solid var(--border);
            color: var(--text-secondary);
            font-weight: 700;
            font-size: 12px;
        }

        .rules-table td {
            padding: 12px;
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
        }

        .rules-table tr:hover td {
            background: #FAFAFA;
        }

        .rule-code {
            font-family: Consolas, monospace;
            background: var(--surface-muted);
            border: 1px solid var(--border);
            padding: 3px 8px;
            border-radius: 4px;
            color: var(--link-blue);
            font-weight: 700;
            font-size: 12px;
        }

        .btn-del {
            height: 32px;
            padding: 0 12px;
            font-size: 12px;
            background: transparent;
            color: var(--live-red);
            border: 1px solid #FECDCA;
            border-radius: 4px;
        }
        .btn-del:hover {
            background: #FEE4E2;
        }

        .btn-sync {
            height: 32px;
            font-size: 12px;
            padding: 0 12px;
        }

        /* 우측 사이드 패널 */
        .sidebar-panel .section {
            padding: 20px;
        }

        .pw-form {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        #pwMsg {
            font-size: 12px;
            min-height: 18px;
        }
    </style>
</head>
<body>

    <!-- 1. 로그인 인증 창 -->
    <div class="auth-container" id="authBox" style="display: block;">
        <div style="margin-bottom: 24px;">
            <div class="brand-badge" style="margin: 0 auto 16px auto; width: 54px; height: 54px; font-size: 22px;">AW</div>
            <h2 style="font-size: 22px; font-weight: 700; margin-bottom: 6px;">Angry Web 대시보드</h2>
            <p style="font-size: 13px; color: var(--text-secondary);">관리자 마스터 비밀번호로 인증하세요</p>
        </div>
        <div style="display: flex; flex-direction: column; gap: 12px;">
            <input type="password" id="authPassword" placeholder="마스터 비밀번호 입력" onkeypress="if(event.key==='Enter') doLogin();">
            <button class="btn-primary" style="height: 48px;" onclick="doLogin()">대시보드 접속</button>
            <div id="authMsg" style="font-size: 13px; color: var(--live-red); min-height: 18px; font-weight: 700;"></div>
        </div>
    </div>

    <!-- 2. 메인 대시보드 -->
    <div class="dashboard-container" id="dashBox">
        <div class="header">
            <div class="brand">
                <div class="brand-badge">AW</div>
                <div class="brand-title">
                    <h2>Angry Web 관리 콘솔</h2>
                    <p>방해 사이트 차단 및 로컬/온라인 정책 제어 센터</p>
                </div>
            </div>
            <div class="header-actions">
                <button class="btn-secondary" onclick="doLogout()">로그아웃</button>
                <button class="btn-primary" onclick="saveAllSettings()">💾 변경사항 즉시 적용</button>
            </div>
        </div>

        <!-- 메인 필터링 활성화 / 비활성화 배너 (Angry Web ON/OFF) -->
        <div class="power-card">
            <div class="power-info">
                <span class="power-status-badge on" id="powerBadge">작동 중 (ON)</span>
                <div class="power-text">
                    <h3 id="powerTitle">Angry Web 필터링이 활성화되어 있습니다</h3>
                    <p id="powerDesc">설정된 차단 정책에 따라 방해 사이트 접속을 선제적으로 차단합니다.</p>
                </div>
            </div>
            <div>
                <label class="switch">
                    <input type="checkbox" id="globalPowerToggle" onchange="toggleGlobalPower(this.checked)">
                    <span class="slider"></span>
                </label>
            </div>
        </div>

        <div class="dashboard-grid">
            <!-- 좌측 메인: 모드 선택 + 로컬 룰 관리 -->
            <div class="main-content">
                <!-- 제재 정책 모드 설정 -->
                <div class="section">
                    <div class="section-header">
                        <div class="section-title">
                            <span>🌐 차단 규칙 정책 모드 선택</span>
                        </div>
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
                            <h4>하이브리드 모드 <span class="mode-badge">추천</span></h4>
                            <p>온라인 룰을 기본 적용하되, <strong>로컬 설정을 최우선</strong>합니다. (로컬에서 비활성화 시 차단 해제)</p>
                        </div>
                    </div>
                </div>

                <!-- 로컬 차단 규칙 관리 -->
                <div class="section">
                    <div class="section-header">
                        <div class="section-title">
                            <span>✏️ 로컬 맞춤 차단 규칙 관리</span>
                        </div>
                        <div>
                            <button class="btn-secondary btn-sync" onclick="syncNow()">🔄 지금 즉시 온라인 동기화</button>
                        </div>
                    </div>

                    <div class="add-rule-form">
                        <input type="text" id="newPattern" placeholder="차단 패턴 (예: *.roblox.com/*, *game*, watch?v=game)">
                        <input type="text" id="newDesc" placeholder="설명 (예: 로블록스 차단)">
                        <button class="btn-primary" onclick="addLocalRule()">+ 추가</button>
                    </div>

                    <div class="notice-box">
                        💡 <strong>하이브리드 우선순위:</strong> 온라인에서 차단 중인 사이트(예: <code>example.com/*</code>)라도, 로컬 목록에 추가하고 체크를 해제(비활성화)하면 <strong>로컬 우선 원칙에 의해 차단되지 않습니다.</strong>
                    </div>

                    <table class="rules-table">
                        <thead>
                            <tr>
                                <th style="width: 60px; text-align: center;">활성</th>
                                <th>차단 패턴</th>
                                <th>설명</th>
                                <th style="width: 80px; text-align: center;">관리</th>
                            </tr>
                        </thead>
                        <tbody id="rulesTableBody">
                            <!-- Dynamic -->
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- 우측 사이드바: 마스터 비밀번호 관리 + 시스템 상태 -->
            <div class="sidebar-panel">
                <div class="section">
                    <div class="section-header">
                        <div class="section-title">
                            <span>🔐 마스터 비밀번호 변경</span>
                        </div>
                    </div>
                    <div class="pw-form">
                        <input type="password" id="curPw" placeholder="현재 비밀번호">
                        <input type="password" id="newPw" placeholder="새 비밀번호">
                        <input type="password" id="newPwConfirm" placeholder="새 비밀번호 확인">
                        <button class="btn-secondary" onclick="changePassword()">비밀번호 저장</button>
                        <div id="pwMsg"></div>
                    </div>
                </div>

                <div class="section" style="background: var(--surface-muted);">
                    <div class="section-title" style="margin-bottom: 10px;">
                        <span>ℹ️ 시스템 가이드</span>
                    </div>
                    <p style="font-size: 12px; color: var(--text-secondary); line-height: 1.6;">
                        - <strong>Angry Web OFF:</strong> 스위치를 끄면 시스템 프록시 필터링이 즉시 바이패스되며 사이트 차단이 중단됩니다.<br>
                        - <strong>단축키:</strong> 언제든 시작 메뉴에서 <code>Angry Web</code>을 검색해 대시보드에 접근할 수 있습니다.
                    </p>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentToken = sessionStorage.getItem('aw_token') || '';
        let currentConfig = null;
        let selectedMode = 'Online';
        let localRules = [];
        let isEnabled = true;

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
                isEnabled = data.isEnabled !== false;

                updatePowerUi(isEnabled);
                setMode(selectedMode, false);
                renderRulesTable();
                updateStats(data);
                showDash();
            } catch (err) {
                alert('설정을 불러오는 중 오류가 발생했습니다.');
            }
        }

        function toggleGlobalPower(checked) {
            isEnabled = checked;
            updatePowerUi(isEnabled);
        }

        function updatePowerUi(on) {
            const toggle = document.getElementById('globalPowerToggle');
            const badge = document.getElementById('powerBadge');
            const title = document.getElementById('powerTitle');
            const desc = document.getElementById('powerDesc');

            toggle.checked = on;
            if (on) {
                badge.className = 'power-status-badge on';
                badge.innerText = '작동 중 (ON)';
                title.innerText = 'Angry Web 필터링이 활성화되어 있습니다';
                desc.innerText = '설정된 차단 정책에 따라 방해 사이트 접속을 선제적으로 차단합니다.';
            } else {
                badge.className = 'power-status-badge off';
                badge.innerText = '꺼짐 (OFF)';
                title.innerText = 'Angry Web 필터링이 중단되었습니다';
                desc.innerText = '모든 사이트 차단이 해제되어 자유롭게 접속할 수 있습니다.';
            }
        }

        function updateStats(data) {
            document.getElementById('statsBar').innerHTML = 
                `온라인 룰: <strong>${data.onlineRulesCount}개</strong> | 로컬 룰: <strong>${localRules.length}개</strong> | 활성 차단 룰: <strong>${data.activeRulesCount}개</strong>`;
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
                tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-tertiary); padding: 24px;">등록된 로컬 룰이 없습니다. 위에서 새로 추가해보세요.</td></tr>';
                return;
            }

            localRules.forEach((rule, idx) => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td style="text-align: center;"><input type="checkbox" style="width: 16px; height: 16px; cursor: pointer; accent-color: var(--naver-green);" ${rule.enabled ? 'checked' : ''} onchange="toggleRule(${idx}, this.checked)"></td>
                    <td><span class="rule-code">${escapeHtml(rule.pattern)}</span></td>
                    <td style="color: var(--text-secondary);">${escapeHtml(rule.description || '-')}</td>
                    <td style="text-align: center;"><button class="btn-del" onclick="deleteRule(${idx})">삭제</button></td>
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
                        isEnabled: isEnabled,
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

        async function syncNow() {
            try {
                const res = await fetch('/api/dashboard/sync-now', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-Dashboard-Token': currentToken
                    }
                });
                const data = await res.json();
                alert(data.message || '온라인 동기화를 진행합니다.');
                setTimeout(loadConfig, 1500);
            } catch (err) {
                alert('동기화 요청 실패');
            }
        }

        async function changePassword() {
            const curPw = document.getElementById('curPw').value;
            const newPw = document.getElementById('newPw').value;
            const confirm = document.getElementById('newPwConfirm').value;
            const msg = document.getElementById('pwMsg');

            if (!curPw || !newPw) {
                msg.style.color = 'var(--live-red)';
                msg.innerText = '현재 비밀번호와 새 비밀번호를 모두 입력하세요.';
                return;
            }
            if (newPw !== confirm) {
                msg.style.color = 'var(--live-red)';
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
                    msg.style.color = 'var(--naver-green)';
                    msg.innerText = data.message;
                    document.getElementById('curPw').value = '';
                    document.getElementById('newPw').value = '';
                    document.getElementById('newPwConfirm').value = '';
                } else {
                    msg.style.color = 'var(--live-red)';
                    msg.innerText = data.message || '변경 실패';
                }
            } catch (err) {
                msg.style.color = 'var(--live-red)';
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
        public bool? IsEnabled { get; set; }
        public string? RuleMode { get; set; }
        public List<RuleDefinition>? LocalRules { get; set; }
        public string? GitHubRulesUrl { get; set; }
    }
}
