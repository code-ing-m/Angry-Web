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
        // Angry Web 전체가 꺼져(OFF)있는 경우 어떠한 규칙도 활성화하지 않음
        if (!_config.IsEnabled)
        {
            return Enumerable.Empty<RuleDefinition>();
        }

        var mode = _config.RuleMode?.Trim() ?? "Online";

        if (string.Equals(mode, "Local", StringComparison.OrdinalIgnoreCase))
        {
            return _config.LocalRules.Where(r => r.Enabled);
        }

        if (string.Equals(mode, "Hybrid", StringComparison.OrdinalIgnoreCase))
        {
            // 하이브리드 모드:
            // 로컬 규칙이 온라인 규칙보다 우선합니다.
            // 1. 로컬에 동일 패턴의 규칙이 존재할 때:
            //    - 로컬 룰이 false(비활성화)면 온라인에서 true여도 제재 X (차단 제외)
            //    - 로컬 룰이 true면 차단 적용
            // 2. 로컬에 없는 온라인 룰은 온라인의 Enabled 상태를 따름
            var localDict = new Dictionary<string, RuleDefinition>(StringComparer.OrdinalIgnoreCase);
            foreach (var lr in _config.LocalRules)
            {
                var norm = NormalizePattern(lr.Pattern);
                if (!string.IsNullOrEmpty(norm))
                {
                    localDict[norm] = lr;
                }
            }

            var result = new List<RuleDefinition>();

            // 온라인 룰 처리: 로컬에서 명시적으로 정의된 패턴이 없을 때만 추가
            foreach (var or in _config.Rules)
            {
                var norm = NormalizePattern(or.Pattern);
                if (!localDict.ContainsKey(norm))
                {
                    if (or.Enabled)
                    {
                        result.Add(or);
                    }
                }
            }

            // 로컬 룰 중 활성화(Enabled == true)된 룰 추가
            foreach (var lr in _config.LocalRules)
            {
                if (lr.Enabled && !string.IsNullOrWhiteSpace(lr.Pattern))
                {
                    result.Add(lr);
                }
            }

            return result;
        }

        // Default: Online mode (or fallback to Local if Rules is empty)
        if (_config.Rules.Count > 0)
        {
            return _config.Rules.Where(r => r.Enabled);
        }

        return _config.LocalRules.Where(r => r.Enabled);
    }

    private static string NormalizePattern(string? pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern)) return string.Empty;
        var p = pattern.Trim();
        if (p.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) p = p.Substring(8);
        else if (p.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) p = p.Substring(7);
        return p.TrimEnd('/');
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
                    _config.AllowedEmbedParents ??= new List<string>();

                    var defaultParents = new[]
                    {
                        "nineschool.co.kr", "ebsi.co.kr", "ebs.co.kr", "megastudy.net",
                        "etoos.com", "mimacstudy.com", "daesungmimac.com", "emath.co.kr",
                        "wedorang.com", "edunet.net"
                    };
                    bool configChanged = false;
                    foreach (var p in defaultParents)
                    {
                        if (!_config.AllowedEmbedParents.Any(x => x.Equals(p, StringComparison.OrdinalIgnoreCase)))
                        {
                            _config.AllowedEmbedParents.Add(p);
                            configChanged = true;
                        }
                    }

                    // 빈 룰 패턴 제거
                    int prevLocalCount = _config.LocalRules.Count;
                    _config.LocalRules = _config.LocalRules.Where(r => !string.IsNullOrWhiteSpace(r.Pattern)).ToList();
                    if (_config.LocalRules.Count != prevLocalCount) configChanged = true;

                    // 비상 복구 키가 없으면 기본 비상 키 생성
                    if (string.IsNullOrEmpty(_config.RecoveryKeyHash))
                    {
                        _config.RecoveryKeyHash = PasswordHelper.HashPassword("ANGRY-SAFE-2026-KEY");
                        configChanged = true;
                    }

                    // 구버전 평문 비밀번호가 저장되어 있다면 자동으로 SHA-256 솔트 해시로 변환하여 파일 저장
                    if (!string.IsNullOrEmpty(_config.MasterPasswordHash) && !_config.MasterPasswordHash.StartsWith("sha256:"))
                    {
                        _config.MasterPasswordHash = PasswordHelper.HashPassword(_config.MasterPasswordHash);
                        configChanged = true;
                    }

                    if (configChanged)
                    {
                        SaveLocalConfig();
                    }

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
            MasterPasswordHash = PasswordHelper.HashPassword("angryweb"),
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
        if (!PasswordHelper.VerifyPassword(_config.MasterPasswordHash, oldPassword))
        {
            return false;
        }

        _config.MasterPasswordHash = PasswordHelper.HashPassword(newPassword);
        SaveLocalConfig();
        _logger.LogInformation("Master password updated successfully with SHA-256 hash.");
        return true;
    }

    public bool ResetPasswordWithRecoveryKey(string recoveryKey, string newPassword)
    {
        if (string.IsNullOrWhiteSpace(recoveryKey) || string.IsNullOrWhiteSpace(_config.RecoveryKeyHash))
        {
            return false;
        }

        if (!PasswordHelper.VerifyPassword(_config.RecoveryKeyHash, recoveryKey.Trim()))
        {
            return false;
        }

        _config.MasterPasswordHash = PasswordHelper.HashPassword(newPassword.Trim());
        SaveLocalConfig();
        _logger.LogInformation("Password reset successfully using recovery key.");
        return true;
    }

    public void UpdateRuleSettings(string mode, List<RuleDefinition> localRules, string? gitHubUrl, bool? isEnabled = null, List<string>? allowedEmbedParents = null, int? syncIntervalMinutes = null)
    {
        _config.RuleMode = mode;
        _config.LocalRules = (localRules ?? new List<RuleDefinition>())
            .Where(r => !string.IsNullOrWhiteSpace(r.Pattern))
            .ToList();
        if (isEnabled.HasValue)
        {
            _config.IsEnabled = isEnabled.Value;
        }
        if (allowedEmbedParents != null)
        {
            _config.AllowedEmbedParents = allowedEmbedParents;
        }
        if (syncIntervalMinutes.HasValue && syncIntervalMinutes.Value > 0)
        {
            _config.SyncIntervalMinutes = syncIntervalMinutes.Value;
        }
        if (!string.IsNullOrWhiteSpace(gitHubUrl))
        {
            _config.GitHubRulesUrl = gitHubUrl.Trim();
        }

        SaveLocalConfig();
        ConfigUpdated?.Invoke();
        _logger.LogInformation("Rule settings updated. Mode: {Mode}, IsEnabled: {Enabled}, LocalRules: {Count}", mode, _config.IsEnabled, _config.LocalRules.Count);
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
