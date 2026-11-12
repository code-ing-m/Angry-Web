namespace AngryWeb.Service.Core;

public class FilterConfig
{
    public string MasterPasswordHash { get; set; } = "angryweb"; // Plain or hashed password
    public string GitHubRulesUrl { get; set; } = "https://raw.githubusercontent.com/code-ing-m/Angry-Web/main/rules.json";
    public int ProxyPort { get; set; } = 8899;
    public int BlockPagePort { get; set; } = 8898;
    public int SyncIntervalMinutes { get; set; } = 10;

    /// <summary>
    /// 규칙 적용 모드:
    /// - "Online": 깃허브 원격 블랙리스트 동기화 및 적용
    /// - "Local": 깃허브 동기화 끄고 로컬에서 만든 룰만 적용
    /// - "Hybrid": 깃허브 원격 룰 + 로컬 추가 룰 병합 적용
    /// </summary>
    public string RuleMode { get; set; } = "Online";

    /// <summary>
    /// Angry Web 필터링 활성화 여부 (ON / OFF)
    /// </summary>
    public bool IsEnabled { get; set; } = true;

    // 깃허브에서 가져온 원격 룰 캐시
    public List<RuleDefinition> Rules { get; set; } = new();

    // 로컬에서 사용자가 직접 추가/관리하는 룰 목록
    public List<RuleDefinition> LocalRules { get; set; } = new();

    public BlockPageContent BlockPage { get; set; } = new();
}

public class RuleDefinition
{
    public string Pattern { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool Enabled { get; set; } = true;
}

public class BlockPageContent
{
    public string Title { get; set; } = "접속이 차단되었습니다 (Angry Web)";
    public string Heading { get; set; } = "집중할 시간입니다!";
    public string SubHeading { get; set; } = "현재 사이트는 블랙리스트 규칙에 의해 차단되었습니다.";
    public string Message { get; set; } = "이 사이트는 생산성 향상을 위해 차단된 사이트입니다. 지금 하는 일에 집중하세요!";
    public string Quote { get; set; } = "오늘 걷지 않으면 내일은 뛰어야 한다.";
}
