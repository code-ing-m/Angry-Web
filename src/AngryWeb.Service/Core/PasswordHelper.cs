using System.Security.Cryptography;
using System.Text;

namespace AngryWeb.Service.Core;

public static class PasswordHelper
{
    private const string SaltPrefix = "ANGRY_WEB_SALT_";

    /// <summary>
    /// 평문 비밀번호를 SHA-256 솔트 해시값으로 변환합니다.
    /// </summary>
    public static string HashPassword(string plainPassword)
    {
        if (string.IsNullOrEmpty(plainPassword))
            return string.Empty;

        // "angryweb" 기본값인 경우에도 해시 처리
        var salted = SaltPrefix + plainPassword;
        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(salted));
        return "sha256:" + Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>
    /// 입력된 비밀번호가 저장된 해시(또는 구버전 평문)와 일치하는지 안전하게 검증합니다.
    /// </summary>
    public static bool VerifyPassword(string storedHashOrPlain, string inputPassword)
    {
        if (string.IsNullOrEmpty(storedHashOrPlain))
            return false;

        // 1. 만약 저장된 값이 sha256 해시인 경우
        if (storedHashOrPlain.StartsWith("sha256:"))
        {
            var hashedInput = HashPassword(inputPassword);
            return CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(storedHashOrPlain),
                Encoding.UTF8.GetBytes(hashedInput)
            );
        }

        // 2. 구버전 평문 비밀번호 호환성 지원 (평문 매칭 시 자동으로 해시로 마이그레이션 가능)
        return string.Equals(storedHashOrPlain, inputPassword, StringComparison.Ordinal);
    }
}

