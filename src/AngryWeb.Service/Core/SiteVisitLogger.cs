using System.Collections.Concurrent;

namespace AngryWeb.Service.Core;

/// <summary>
/// 아이가 방문한 모든 사이트를 메모리 + JSON 파일에 기록합니다.
/// 차단/허용 여부, 시각, URL, 매칭된 룰을 함께 보관합니다.
/// 최대 500건 메모리, 파일 보관 최대 2000건 (오래된 항목 자동 삭제).
/// </summary>
public class SiteVisitLogger
{
    private readonly ILogger<SiteVisitLogger> _logger;
    private readonly string _logFilePath;
    private readonly object _fileLock = new();
    private readonly ConcurrentQueue<VisitEntry> _memoryLog = new();
    private const int MaxMemoryEntries = 500;
    private const int MaxFileEntries = 2000;

    public SiteVisitLogger(ILogger<SiteVisitLogger> logger)
    {
        _logger = logger;
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var dir = Path.Combine(appData, "AngryWeb");
        Directory.CreateDirectory(dir);
        _logFilePath = Path.Combine(dir, "visit_log.json");
    }

    public void Record(string url, string host, bool blocked, string? matchedRule = null, bool embedAllowed = false)
    {
        var entry = new VisitEntry
        {
            Timestamp = DateTime.Now,
            Url = url,
            Host = host,
            Blocked = blocked,
            EmbedAllowed = embedAllowed,
            MatchedRule = matchedRule
        };

        // 메모리 큐에 추가
        _memoryLog.Enqueue(entry);
        while (_memoryLog.Count > MaxMemoryEntries)
            _memoryLog.TryDequeue(out _);

        // 파일에 비동기 기록
        Task.Run(() => AppendToFile(entry));
    }

    /// <summary>메모리 캐시에서 최신 순으로 반환</summary>
    public List<VisitEntry> GetRecent(int count = 200)
    {
        return _memoryLog.OrderByDescending(e => e.Timestamp).Take(count).ToList();
    }

    /// <summary>파일에서 전체 로그 읽기 (페이징)</summary>
    public List<VisitEntry> GetFromFile(int page = 1, int pageSize = 100, string? filterHost = null, bool? filterBlocked = null)
    {
        try
        {
            lock (_fileLock)
            {
                if (!File.Exists(_logFilePath)) return new();
                var lines = File.ReadAllLines(_logFilePath);
                var entries = new List<VisitEntry>();
                // 최신 순 (파일 뒤에서 읽기)
                for (int i = lines.Length - 1; i >= 0; i--)
                {
                    var line = lines[i].Trim();
                    if (string.IsNullOrEmpty(line)) continue;
                    try
                    {
                        var e = System.Text.Json.JsonSerializer.Deserialize<VisitEntry>(line);
                        if (e == null) continue;
                        if (filterHost != null && !e.Host.Contains(filterHost, StringComparison.OrdinalIgnoreCase)) continue;
                        if (filterBlocked.HasValue && e.Blocked != filterBlocked.Value) continue;
                        entries.Add(e);
                    }
                    catch { }
                }
                return entries.Skip((page - 1) * pageSize).Take(pageSize).ToList();
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Failed to read visit log: {Msg}", ex.Message);
            return new();
        }
    }

    public int GetTotalCount(bool? filterBlocked = null)
    {
        try
        {
            lock (_fileLock)
            {
                if (!File.Exists(_logFilePath)) return 0;
                var lines = File.ReadAllLines(_logFilePath);
                if (filterBlocked == null) return lines.Count(l => !string.IsNullOrWhiteSpace(l));
                int count = 0;
                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    try
                    {
                        var e = System.Text.Json.JsonSerializer.Deserialize<VisitEntry>(line);
                        if (e != null && e.Blocked == filterBlocked.Value) count++;
                    }
                    catch { }
                }
                return count;
            }
        }
        catch { return 0; }
    }

    public void ClearLog()
    {
        try
        {
            lock (_fileLock)
            {
                File.WriteAllText(_logFilePath, string.Empty);
            }
            while (_memoryLog.TryDequeue(out _)) { }
            _logger.LogInformation("Visit log cleared.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Failed to clear visit log: {Msg}", ex.Message);
        }
    }

    private void AppendToFile(VisitEntry entry)
    {
        try
        {
            lock (_fileLock)
            {
                var line = System.Text.Json.JsonSerializer.Serialize(entry) + Environment.NewLine;
                File.AppendAllText(_logFilePath, line);

                // 파일 최대 크기 제한: 2000건 초과 시 오래된 항목 제거
                var lines = File.ReadAllLines(_logFilePath);
                if (lines.Length > MaxFileEntries)
                {
                    var trimmed = lines.TakeLast(MaxFileEntries).ToArray();
                    File.WriteAllLines(_logFilePath, trimmed);
                }
            }
        }
        catch { /* 로그 기록 실패는 무시 */ }
    }
}

public class VisitEntry
{
    public DateTime Timestamp { get; set; }
    public string Url { get; set; } = string.Empty;
    public string Host { get; set; } = string.Empty;
    public bool Blocked { get; set; }
    public bool EmbedAllowed { get; set; }
    public string? MatchedRule { get; set; }
}

