using AngryWeb.Service.Core;

namespace AngryWeb.Service;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly ConfigManager _configManager;
    private readonly PatternMatcher _patternMatcher;
    private readonly BlockPageServer _blockPageServer;
    private readonly ProxyFilterEngine _proxyFilterEngine;
    private readonly AutoUpdateManager _autoUpdateManager;

    public Worker(
        ILogger<Worker> logger,
        ConfigManager configManager,
        PatternMatcher patternMatcher,
        BlockPageServer blockPageServer,
        ProxyFilterEngine proxyFilterEngine,
        AutoUpdateManager autoUpdateManager)
    {
        _logger = logger;
        _configManager = configManager;
        _patternMatcher = patternMatcher;
        _blockPageServer = blockPageServer;
        _proxyFilterEngine = proxyFilterEngine;
        _autoUpdateManager = autoUpdateManager;

        _configManager.ConfigUpdated += OnConfigUpdated;
    }

    private void OnConfigUpdated()
    {
        _logger.LogInformation("Configuration updated, reloading pattern rules...");
        _patternMatcher.LoadRules(_configManager.GetActiveRules());
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Angry Web Service is starting at: {time}", DateTimeOffset.Now);

        // 1. Initial rule compile from active rules
        _patternMatcher.LoadRules(_configManager.GetActiveRules());

        // 2. Start Block Page server
        _blockPageServer.Start(_configManager.CurrentConfig.BlockPagePort);

        // 3. Start Proxy Filter Engine (로컬 필터링 즉각 개시)
        _proxyFilterEngine.Start();

        // 4. PC 부팅 후 인터넷 연결이 완료될 때까지 비동기 대기
        _ = Task.Run(async () =>
        {
            try
            {
                await _autoUpdateManager.WaitForInternetConnectionAsync(stoppingToken);

                // 인터넷 연결 확인 즉시 GitHub 자가 업데이트 확인 및 규칙 동기화
                await _autoUpdateManager.CheckAndApplyUpdateAsync(stoppingToken);
                await _configManager.SyncWithGitHubAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning("인터넷 대기 및 초기 동기화 중 오류: {Msg}", ex.Message);
            }
        }, stoppingToken);

        // 5. Periodic GitHub Sync loop
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var interval = Math.Max(1, _configManager.CurrentConfig.SyncIntervalMinutes);
                await Task.Delay(TimeSpan.FromMinutes(interval), stoppingToken);
                await _configManager.SyncWithGitHubAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in periodic sync loop.");
            }
        }
    }

    public override Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Angry Web Service is stopping...");
        _proxyFilterEngine.Stop();
        _blockPageServer.Stop();
        return base.StopAsync(cancellationToken);
    }
}
