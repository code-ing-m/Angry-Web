using System.Collections.Concurrent;

namespace AngryWeb.Service.Core;

public class TemporaryAccessManager
{
    // Dictionary of Allowed Host or URL -> Expiration time
    private readonly ConcurrentDictionary<string, DateTime> _temporaryAllowed = new(StringComparer.OrdinalIgnoreCase);

    public void Allow(string target, TimeSpan duration)
    {
        var expiry = DateTime.UtcNow.Add(duration);
        var normalized = Normalize(target);
        _temporaryAllowed[normalized] = expiry;

        // target에서 호스트(도메인) 부분만 추출하여 호스트 전체도 허용 목록에 등록
        var host = ExtractHost(target);
        if (!string.IsNullOrEmpty(host))
        {
            _temporaryAllowed[host] = expiry;
        }
    }

    public bool IsAllowed(string target)
    {
        var normalized = Normalize(target);
        var targetHost = ExtractHost(target);

        // 1. 직접 매칭 확인
        if (CheckDirect(normalized) || (!string.IsNullOrEmpty(targetHost) && CheckDirect(targetHost)))
        {
            return true;
        }

        // 2. 부분 일치 및 상위 도메인 매칭 확인
        foreach (var kvp in _temporaryAllowed)
        {
            if (DateTime.UtcNow < kvp.Value)
            {
                var key = kvp.Key;
                if (normalized.Contains(key, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
                if (!string.IsNullOrEmpty(targetHost) && 
                    (targetHost.Equals(key, StringComparison.OrdinalIgnoreCase) || targetHost.EndsWith("." + key, StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private bool CheckDirect(string key)
    {
        if (_temporaryAllowed.TryGetValue(key, out var expiry))
        {
            if (DateTime.UtcNow < expiry)
            {
                return true;
            }
            _temporaryAllowed.TryRemove(key, out _);
        }
        return false;
    }

    private static string ExtractHost(string target)
    {
        try
        {
            var t = target.Trim();
            if (!t.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !t.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                t = "https://" + t;
            }
            if (Uri.TryCreate(t, UriKind.Absolute, out var uri))
            {
                return uri.Host.ToLowerInvariant();
            }
        }
        catch { }
        return string.Empty;
    }

    private static string Normalize(string target)
    {
        var t = target.Trim();
        if (t.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            t = t.Substring(8);
        else if (t.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            t = t.Substring(7);
        return t.TrimEnd('/');
    }
}
