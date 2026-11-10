using System.Text.Json;

namespace AngryWeb.Service.Core;

public class ConfigManager
{
    private readonly ILogger<ConfigManager> _logger;
    private readonly HttpClient _httpClient = new();
    private FilterConfig _config = new();
    private readonly string _localConfigPath;

    public FilterConfig CurrentConfig => _config;

    public event Action? ConfigUpdated;

    public ConfigManager(ILogger<ConfigManager> logger)
    {
        _logger = logger;
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var dir = Path.Combine(appData, "AngryWeb");
        Directory.CreateDirectory(dir);
        _localConfigPath = Path.Combine(dir, "config.json");

        LoadLocalConfig();
    }

    /// <summary>
    /// 현재 모드(RuleMode)에 맞춰 실제 필터링에 사용할 최종 규칙 목록을 반환합니다.
    /// </summary>
    public IEnumerable<RuleDefinition> GetActiveRules()
    {
        var mode = _config.RuleMode?.Trim() ?? "Online";

        if (string.Equals(mode, "Local", StringComparison.OrdinalIgnoreCase))
        {
            return _config.LocalRules.Where(r => r.Enabled);
        }

        if (string.Equals(mode, "Hybrid", StringComparison.OrdinalIgnoreCase))
        {
            return _config.Rules.Where(r => r.Enabled)
                .Concat(_config.LocalRules.Where(r => r.Enabled));
        }

        // Default: Online mode (or fallback to Local if Rules is empty)
        if (_config.Rules.Count > 0)
        {
            return _config.Rules.Where(r => r.Enabled);
        }

        return _config.LocalRules.Where(r => r.Enabled);
    }

    public void LoadLocalConfig()
    {
        try
        {
            if (File.Exists(_localConfigPath))
            {
                var json = File.ReadAllText(_localConfigPath);
                var loaded = JsonSerializer.Deserialize<FilterConfig>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (loaded != null)
                {
                    _config = loaded;
                    _config.LocalRules ??= new List<RuleDefinition>();
                    _config.Rules ??= new List<RuleDefinition>();
                    _logger.LogInformation("Loaded local configuration from {Path}", _localConfigPath);
                    return;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load local config, using defaults.");
        }

        _config = new FilterConfig
        {
            LocalRules = new List<RuleDefinition>
            {
                new() { Pattern = "youtube.com/shorts/*", Description = "YouTube Shorts 차단", Enabled = true },
                new() { Pattern = "*.tiktok.com/*", Description = "틱톡 전면 차단", Enabled = true },
                new() { Pattern = "instagram.com/reels/*", Description = "인스타그램 릴스 차단", Enabled = true },
                new() { Pattern = "*chzzk.naver.com*", Description = "치지직 방송 차단", Enabled = true }
            }
        };
        SaveLocalConfig();
    }

    public void SaveLocalConfig()
    {
        try
        {
            var json = JsonSerializer.Serialize(_config, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_localConfigPath, json);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save local config.");
        }
    }

    public bool UpdatePassword(string oldPassword, string newPassword)
    {
        if (!string.Equals(_config.MasterPasswordHash, oldPassword, StringComparison.Ordinal))
        {
            return false;
        }

        _config.MasterPasswordHash = newPassword;
        SaveLocalConfig();
        _logger.LogInformation("Master password updated successfully.");
        return true;
    }

    public void UpdateRuleSettings(string mode, List<RuleDefinition> localRules, string? gitHubUrl)
    {
        _config.RuleMode = mode;
        _config.LocalRules = localRules;
        if (!string.IsNullOrWhiteSpace(gitHubUrl))
        {
            _config.GitHubRulesUrl = gitHubUrl.Trim();
        }

        SaveLocalConfig();
        ConfigUpdated?.Invoke();
        _logger.LogInformation("Rule settings updated. Mode: {Mode}, LocalRules: {Count}", mode, localRules.Count);
    }

    public async Task SyncWithGitHubAsync(CancellationToken ct = default)
    {
        // Local 모드일 때는 깃허브 원격 동기화 건너뜀
        if (string.Equals(_config.RuleMode, "Local", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogDebug("Sync skipped because RuleMode is 'Local'.");
            return;
        }

        if (string.IsNullOrWhiteSpace(_config.GitHubRulesUrl))
            return;

        try
        {
            _logger.LogInformation("Syncing rules from GitHub: {Url}", _config.GitHubRulesUrl);
            var response = await _httpClient.GetAsync(_config.GitHubRulesUrl, ct);
            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync(ct);
                var remoteConfig = JsonSerializer.Deserialize<FilterConfig>(content, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (remoteConfig != null && remoteConfig.Rules.Count > 0)
                {
                    _config.Rules = remoteConfig.Rules;
                    if (remoteConfig.BlockPage != null)
                    {
                        _config.BlockPage = remoteConfig.BlockPage;
                    }
                    SaveLocalConfig();
                    ConfigUpdated?.Invoke();
                    _logger.LogInformation("Successfully synced {Count} rules from GitHub.", _config.Rules.Count);
                }
            }
            else
            {
                _logger.LogWarning("GitHub sync returned status code: {Status}", response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning("GitHub sync skipped: {Message}", ex.Message);
        }
    }
}
