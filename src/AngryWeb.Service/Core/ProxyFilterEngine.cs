using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Models;

namespace AngryWeb.Service.Core;

public class ProxyFilterEngine : IDisposable
{
    private readonly ILogger<ProxyFilterEngine> _logger;
    private readonly ConfigManager _configManager;
    private readonly PatternMatcher _patternMatcher;
    private readonly TemporaryAccessManager _accessManager;
    private readonly SiteVisitLogger _visitLogger;
    private readonly ProxyServer _proxyServer;
    private ExplicitProxyEndPoint? _explicitEndPoint;
    private CancellationTokenSource? _watchdogCts;

    [DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

    private const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
    private const int INTERNET_OPTION_REFRESH = 37;

    public ProxyFilterEngine(
        ILogger<ProxyFilterEngine> logger,
        ConfigManager configManager,
        PatternMatcher patternMatcher,
        TemporaryAccessManager accessManager,
        SiteVisitLogger visitLogger)
    {
        _logger = logger;
        _configManager = configManager;
        _patternMatcher = patternMatcher;
        _accessManager = accessManager;
        _visitLogger = visitLogger;

        _proxyServer = new ProxyServer();
        // Trust Root Certificate automatically on Windows
        _proxyServer.CertificateManager.CertificateValidDays = 365;
        _proxyServer.CertificateManager.RootCertificateName = "Angry Web Filter Root CA";
        _proxyServer.CertificateManager.RootCertificateIssuerName = "Angry Web Security Engine";

        _proxyServer.BeforeRequest += OnBeforeRequest;
        _proxyServer.BeforeResponse += OnBeforeResponse;
        _proxyServer.ServerCertificateValidationCallback += OnCertificateValidation;
    }

    public void Start()
    {
        var config = _configManager.CurrentConfig;

        // Ensure Root Certificate is trusted
        try
        {
            _proxyServer.CertificateManager.CreateRootCertificate();
            _proxyServer.CertificateManager.TrustRootCertificate(true);
            _logger.LogInformation("Root Certificate installed and trusted.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to trust root certificate automatically. Admin privileges may be needed.");
        }

        _explicitEndPoint = new ExplicitProxyEndPoint(IPAddress.Any, config.ProxyPort, true);
        _explicitEndPoint.BeforeTunnelConnectRequest += OnBeforeTunnelConnectRequest;
        _proxyServer.AddEndPoint(_explicitEndPoint);
        _proxyServer.Start();

        // 1. Titanium proxy built-in system proxy registration
        try
        {
            _proxyServer.SetAsSystemProxy(_explicitEndPoint, ProxyProtocolType.AllHttp);
            _logger.LogInformation("AngryWeb proxy running on port {Port} and configured as System Proxy.", config.ProxyPort);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not set system proxy via Titanium.");
        }

        // 2. Windows registry enforcement (HKCU and all logged-in user profiles via HKU)
        ApplyWindowsProxyRegistry(true, $"127.0.0.1:{config.ProxyPort}");

        // 3. 실시간 프록시 레지스트리 감시 및 강제 유지 Watchdog 시작
        StartProxyWatchdog();
    }

    public void Stop()
    {
        try
        {
            _watchdogCts?.Cancel();
            ApplyWindowsProxyRegistry(false, null);

            if (_explicitEndPoint != null)
            {
                _proxyServer.DisableSystemProxy(ProxyProtocolType.AllHttp);
            }
            _proxyServer.Stop();
            _logger.LogInformation("Proxy stopped and system proxy settings restored.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while stopping proxy server.");
        }
    }

    private void StartProxyWatchdog()
    {
        _watchdogCts = new CancellationTokenSource();
        var ct = _watchdogCts.Token;

        Task.Run(async () =>
        {
            _logger.LogInformation("Proxy settings watchdog started.");
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(2000, ct);

                    var cfg = _configManager.CurrentConfig;
                    // Angry Web이 전체 활성화(IsEnabled == true)되어 있을 때만 프록시 강제 유지
                    if (cfg.IsEnabled)
                    {
                        var proxyAddr = $"127.0.0.1:{cfg.ProxyPort}";
                        ApplyWindowsProxyRegistry(true, proxyAddr);
                    }
                    else
                    {
                        ApplyWindowsProxyRegistry(false, null);
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Watchdog tick error");
                }
            }
        }, ct);
    }

    private static void NotifyWinInet()
    {
        try
        {
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);
        }
        catch { }
    }

    private void ApplyWindowsProxyRegistry(bool enable, string? proxyServer)
    {
        try
        {
            // 1. Current User (if running under user session)
            using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", true))
            {
                if (key != null)
                {
                    key.SetValue("ProxyEnable", enable ? 1 : 0, RegistryValueKind.DWord);
                    if (enable && !string.IsNullOrEmpty(proxyServer))
                    {
                        key.SetValue("ProxyServer", proxyServer, RegistryValueKind.String);
                        key.SetValue("ProxyOverride", "localhost;127.0.0.1;<local>", RegistryValueKind.String);
                    }
                }
            }

            // 2. All active user profiles in HKEY_USERS (Crucial when running as Windows Service / SYSTEM account)
            var usersKey = Registry.Users;
            foreach (var subKeyName in usersKey.GetSubKeyNames())
            {
                // Skip system/service accounts and classes (.DEFAULT, S-1-5-18, _Classes)
                if (subKeyName.StartsWith(".DEFAULT") || subKeyName.EndsWith("_Classes") || subKeyName.Equals("S-1-5-18") || subKeyName.Equals("S-1-5-19") || subKeyName.Equals("S-1-5-20"))
                    continue;

                try
                {
                    using var userInternetSettings = usersKey.OpenSubKey($@"{subKeyName}\Software\Microsoft\Windows\CurrentVersion\Internet Settings", true);
                    if (userInternetSettings != null)
                    {
                        userInternetSettings.SetValue("ProxyEnable", enable ? 1 : 0, RegistryValueKind.DWord);
                        if (enable && !string.IsNullOrEmpty(proxyServer))
                        {
                            userInternetSettings.SetValue("ProxyServer", proxyServer, RegistryValueKind.String);
                            userInternetSettings.SetValue("ProxyOverride", "localhost;127.0.0.1;<local>", RegistryValueKind.String);
                        }
                    }
                }
                catch { }
            }

            NotifyWinInet();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to apply Windows proxy registry.");
        }
    }

    private Task OnCertificateValidation(object sender, CertificateValidationEventArgs e)
    {
        // Accept valid upstream certificates
        if (e.SslPolicyErrors == System.Net.Security.SslPolicyErrors.None)
        {
            e.IsValid = true;
        }
        return Task.CompletedTask;
    }

    /// <summary>
    /// HTTPS CONNECT 터널링 단계에서 도메인 레벨 차단을 선제적으로 처리합니다.
    /// </summary>
    private Task OnBeforeTunnelConnectRequest(object sender, TunnelConnectSessionEventArgs e)
    {
        var hostname = e.HttpClient.Request.RequestUri.Host;

        if (hostname.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            hostname.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase))
        {
            return Task.CompletedTask;
        }

        if (_accessManager.IsAllowed(hostname))
        {
            return Task.CompletedTask;
        }

        // Test with simulated HTTPS URL to check domain-wide blocking (e.g. *.crazygames.com/*)
        var testUrl = $"https://{hostname}/";
        if (_patternMatcher.IsBlocked(testUrl, out var matchedRule))
        {
            _logger.LogInformation("[TUNNEL BLOCKED] {Host} matched rule: {Rule}", hostname, matchedRule);

            // Decrypt SSL to allow graceful redirect to local block page in OnBeforeRequest
            e.DecryptSsl = true;
        }

        return Task.CompletedTask;
    }

    private async Task OnBeforeRequest(object sender, SessionEventArgs e)
    {
        var fullUrl = e.HttpClient.Request.Url;
        var host = e.HttpClient.Request.RequestUri.Host;

        // Skip internal/local requests
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            host.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        // Check if temporarily allowed by password bypass
        if (_accessManager.IsAllowed(fullUrl) || _accessManager.IsAllowed(host))
        {
            _visitLogger.Record(fullUrl, host, blocked: false);
            return;
        }

        // 인강 등 허용된 상위 사이트(Referer/Origin)에서 임베드된 요청인지 확인 (인강 유튜브 플레이어 허용)
        if (IsAllowedEmbedRequest(e))
        {
            _logger.LogInformation("[EMBED ALLOWED] Allowed media request for {Url} from parent site", fullUrl);
            _visitLogger.Record(fullUrl, host, blocked: false, embedAllowed: true);
            return;
        }

        // Check against PatternMatcher
        if (_patternMatcher.IsBlocked(fullUrl, out var matchedRule))
        {
            _logger.LogInformation("[BLOCKED] {Url} matched rule: {Rule}", fullUrl, matchedRule);
            _visitLogger.Record(fullUrl, host, blocked: true, matchedRule: matchedRule);

            // Redirect to local block page
            var blockPort = _configManager.CurrentConfig.BlockPagePort;
            var redirectUrl = $"http://127.0.0.1:{blockPort}/?target={Uri.EscapeDataString(fullUrl)}&rule={Uri.EscapeDataString(matchedRule ?? "")}";

            // If HTML navigation or standard browser GET, redirect with 302
            if (e.HttpClient.Request.Method == "GET")
            {
                e.Ok($"<!DOCTYPE html><html><head><meta http-equiv='refresh' content='0;url={redirectUrl}'><script>window.location.replace('{redirectUrl}');</script></head><body>Redirecting to block page...</body></html>");
                return;
            }

            // Or respond with custom 403 HTML directly
            e.GenericResponse(
                $"<!DOCTYPE html><html><head><meta http-equiv='refresh' content='0;url={redirectUrl}'><script>window.location.replace('{redirectUrl}');</script></head><body><h1>Blocked by Angry Web</h1></body></html>",
                HttpStatusCode.Forbidden,
                new Dictionary<string, HttpHeader>
                {
                    { "Location", new HttpHeader("Location", redirectUrl) },
                    { "Content-Type", new HttpHeader("Content-Type", "text/html; charset=utf-8") }
                });
        }
        else
        {
            // 차단되지 않은 일반 허용 사이트도 기록 (GET 요청만, 너무 많은 리소스 요청 제외)
            if (e.HttpClient.Request.Method == "GET" && !fullUrl.Contains("favicon") && !fullUrl.EndsWith(".js") && !fullUrl.EndsWith(".css") && !fullUrl.EndsWith(".png") && !fullUrl.EndsWith(".jpg") && !fullUrl.EndsWith(".gif") && !fullUrl.EndsWith(".woff2"))
            {
                _visitLogger.Record(fullUrl, host, blocked: false);
            }
        }
    }

    private bool IsAllowedEmbedRequest(SessionEventArgs e)
    {
        var referer = e.HttpClient.Request.Headers.FirstOrDefault(h => h.Name.Equals("Referer", StringComparison.OrdinalIgnoreCase))?.Value;
        var origin = e.HttpClient.Request.Headers.FirstOrDefault(h => h.Name.Equals("Origin", StringComparison.OrdinalIgnoreCase))?.Value;

        var allowedParents = _configManager.CurrentConfig.AllowedEmbedParents ?? new List<string>();
        if (allowedParents.Count == 0) return false;

        foreach (var parent in allowedParents)
        {
            if (string.IsNullOrWhiteSpace(parent)) continue;
            var cleanParent = parent.Trim().ToLowerInvariant();

            if (!string.IsNullOrEmpty(referer) && referer.ToLowerInvariant().Contains(cleanParent))
            {
                return true;
            }
            if (!string.IsNullOrEmpty(origin) && origin.ToLowerInvariant().Contains(cleanParent))
            {
                return true;
            }
        }

        return false;
    }

    private Task OnBeforeResponse(object sender, SessionEventArgs e)
    {
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        Stop();
        _proxyServer.Dispose();
    }
}
