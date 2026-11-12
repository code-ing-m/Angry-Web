using AngryWeb.Service.Core;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AngryWeb.Tests;

public class HybridRuleOverrideTests
{
    [Fact]
    public void HybridMode_WhenLocalRuleIsDisabled_OverridesOnlineEnabledRule()
    {
        var configManager = new ConfigManager(NullLogger<ConfigManager>.Instance);

        // 1. 온라인 룰에 example.com/* (Enabled = true) 추가
        configManager.CurrentConfig.Rules = new List<RuleDefinition>
        {
            new() { Pattern = "example.com/*", Enabled = true, Description = "온라인 룰" },
            new() { Pattern = "badsite.com/*", Enabled = true, Description = "온라인 나쁜사이트" }
        };

        // 2. 로컬 룰에 example.com/* (Enabled = false) 설정
        configManager.CurrentConfig.LocalRules = new List<RuleDefinition>
        {
            new() { Pattern = "example.com/*", Enabled = false, Description = "로컬에서 예외 허용" },
            new() { Pattern = "custom-block.com/*", Enabled = true, Description = "로컬 차단" }
        };

        // 3. 모드를 Hybrid로 설정
        configManager.CurrentConfig.RuleMode = "Hybrid";
        configManager.CurrentConfig.IsEnabled = true;

        var activeRules = configManager.GetActiveRules().ToList();

        // 검증:
        // - example.com/* 은 로컬에서 false이므로 activeRules에 포함되지 않아야 함 (제재 X)
        // - badsite.com/* 은 로컬에 없으므로 온라인 true 유지
        // - custom-block.com/* 은 로컬 true이므로 포함
        Assert.DoesNotContain(activeRules, r => r.Pattern.Contains("example.com"));
        Assert.Contains(activeRules, r => r.Pattern.Contains("badsite.com"));
        Assert.Contains(activeRules, r => r.Pattern.Contains("custom-block.com"));
    }

    [Fact]
    public void DisabledAngryWeb_ReturnsNoActiveRules()
    {
        var configManager = new ConfigManager(NullLogger<ConfigManager>.Instance);
        configManager.CurrentConfig.Rules = new List<RuleDefinition>
        {
            new() { Pattern = "badsite.com/*", Enabled = true }
        };
        configManager.CurrentConfig.LocalRules = new List<RuleDefinition>
        {
            new() { Pattern = "custom.com/*", Enabled = true }
        };

        configManager.CurrentConfig.IsEnabled = false;

        var activeRules = configManager.GetActiveRules().ToList();
        Assert.Empty(activeRules);
    }
}

