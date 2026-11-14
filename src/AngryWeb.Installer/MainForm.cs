using System.Diagnostics;
using System.Reflection;
using System.Text;

namespace AngryWeb.Installer;

public partial class MainForm : Form
{
    private const string ServiceName = "AngryWebService";
    private readonly string _installDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "AngryWeb");
    private readonly string _dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AngryWeb");

    private ProgressBar _progressBar = null!;
    private Label _lblStatus = null!;
    private TextBox _txtPassword = null!;
    private Button _btnInstall = null!;
    private Button _btnUninstall = null!;

    public MainForm()
    {
        InitializeCustomComponents();
        CheckCurrentStatus();
    }

    private void InitializeCustomComponents()
    {
        Text = "Angry Web - 설치 마법사";
        Size = new Size(520, 420);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(248, 249, 250);
        Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);

        // Header Panel
        var header = new Panel
        {
            Dock = DockStyle.Top,
            Height = 85,
            BackColor = Color.FromArgb(22, 27, 34)
        };
        var lblTitle = new Label
        {
            Text = "Angry Web 설치 마법사",
            Font = new Font("Segoe UI", 14f, FontStyle.Bold),
            ForeColor = Color.White,
            Location = new Point(24, 18),
            AutoSize = true
        };
        var lblSubtitle = new Label
        {
            Text = "집중력 유지를 위한 웹 사이트 차단 및 필터링 시스템",
            Font = new Font("Segoe UI", 9f),
            ForeColor = Color.FromArgb(139, 148, 158),
            Location = new Point(25, 48),
            AutoSize = true
        };
        header.Controls.Add(lblTitle);
        header.Controls.Add(lblSubtitle);
        Controls.Add(header);

        // Body Elements
        var lblInfo = new Label
        {
            Text = "설치 시 Windows 백그라운드 서비스로 등록되어 자동 실행됩니다.\n임의 종료 및 제거를 방어하기 위한 관리자 비밀번호를 설정하세요.",
            Location = new Point(25, 105),
            Size = new Size(460, 40),
            ForeColor = Color.FromArgb(36, 41, 47)
        };
        Controls.Add(lblInfo);

        var lblPw = new Label
        {
            Text = "마스터 비밀번호:",
            Location = new Point(25, 158),
            AutoSize = true,
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold)
        };
        Controls.Add(lblPw);

        _txtPassword = new TextBox
        {
            Location = new Point(145, 155),
            Size = new Size(220, 26),
            Text = "angryweb",
            UseSystemPasswordChar = true
        };
        Controls.Add(_txtPassword);

        var chkShowPw = new CheckBox
        {
            Text = "표시",
            Location = new Point(375, 155),
            AutoSize = true
        };
        chkShowPw.CheckedChanged += (s, e) => _txtPassword.UseSystemPasswordChar = !chkShowPw.Checked;
        Controls.Add(chkShowPw);

        _progressBar = new ProgressBar
        {
            Location = new Point(25, 205),
            Size = new Size(455, 22),
            Style = ProgressBarStyle.Continuous,
            Value = 0
        };
        Controls.Add(_progressBar);

        _lblStatus = new Label
        {
            Text = "준비 완료. 설치 버튼을 누르세요.",
            Location = new Point(25, 235),
            Size = new Size(455, 30),
            ForeColor = Color.FromArgb(87, 96, 106)
        };
        Controls.Add(_lblStatus);

        // Buttons
        _btnInstall = new Button
        {
            Text = "지금 설치하기",
            Location = new Point(235, 290),
            Size = new Size(130, 40),
            BackColor = Color.FromArgb(46, 160, 67),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            Cursor = Cursors.Hand
        };
        _btnInstall.FlatAppearance.BorderSize = 0;
        _btnInstall.Click += BtnInstall_Click;
        Controls.Add(_btnInstall);

        _btnUninstall = new Button
        {
            Text = "제거하기",
            Location = new Point(380, 290),
            Size = new Size(100, 40),
            BackColor = Color.FromArgb(207, 34, 46),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            Cursor = Cursors.Hand
        };
        _btnUninstall.FlatAppearance.BorderSize = 0;
        _btnUninstall.Click += BtnUninstall_Click;
        Controls.Add(_btnUninstall);
    }

    private void CheckCurrentStatus()
    {
        var isInstalled = RunCmd("sc.exe", $"query {ServiceName}").Contains("RUNNING") ||
                          RunCmd("sc.exe", $"query {ServiceName}").Contains("STOPPED");
        if (isInstalled)
        {
            _lblStatus.Text = "현재 Angry Web 서비스가 설치되어 있습니다.";
            _btnInstall.Text = "다시 설치 (업데이트)";
            _btnUninstall.Enabled = true;
        }
        else
        {
            _lblStatus.Text = "설치 준비가 되었습니다.";
            _btnUninstall.Enabled = false;
        }
    }

    private async void BtnInstall_Click(object? sender, EventArgs e)
    {
        var pw = _txtPassword.Text.Trim();
        if (string.IsNullOrEmpty(pw))
        {
            MessageBox.Show("보안을 위해 마스터 비밀번호를 반드시 입력해주세요.", "알림", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        SetUiEnabled(false);
        _progressBar.Value = 10;
        _lblStatus.Text = "설치 파일 준비 중...";

        await Task.Run(() =>
        {
            try
            {
                // 1. 기존 서비스 중지 및 프로세스 완전 종료 대기
                RunCmd("sc.exe", $"stop {ServiceName}");
                for (int i = 0; i < 10; i++)
                {
                    Thread.Sleep(500);
                    var query = RunCmd("sc.exe", $"query {ServiceName}");
                    if (!query.Contains("RUNNING")) break;
                }
                // 만약 여전히 잡혀있다면 강제 종료 시도
                RunCmd("taskkill.exe", "/F /IM AngryWeb.Service.exe");
                Thread.Sleep(1000);

                // 2. 디렉토리 생성
                Directory.CreateDirectory(_installDir);
                Directory.CreateDirectory(_dataDir);

                // 3. 임베디드 리소스 추출
                Invoke(() => { _progressBar.Value = 40; _lblStatus.Text = "실행 파일 및 구성 복사 중..."; });
                var targetExe = Path.Combine(_installDir, "AngryWeb.Service.exe");
                ExtractResource("AngryWeb.Installer.Resources.AngryWeb.Service.exe", targetExe);

                // 4. config.json 설정 저장 (임베디드된 최신 rules.json 기반)
                var configPath = Path.Combine(_dataDir, "config.json");
                var hashedPw = HashPassword(pw);
                try
                {
                    ExtractResource("AngryWeb.Installer.Resources.rules.json", configPath);
                    var rawJson = File.ReadAllText(configPath);
                    // 비밀번호를 SHA-256 해시값으로 안전하게 치환
                    var updatedJson = System.Text.RegularExpressions.Regex.Replace(rawJson, "\"MasterPasswordHash\":\\s*\"(.*?)\"", $"\"MasterPasswordHash\": \"{hashedPw}\"");
                    File.WriteAllText(configPath, updatedJson);
                }
                catch
                {
                    // Fallback
                    File.WriteAllText(configPath, $$"""{"MasterPasswordHash":"{{hashedPw}}","GitHubRulesUrl":"https://raw.githubusercontent.com/code-ing-m/Angry-Web/main/rules.json","ProxyPort":8899,"BlockPagePort":8898,"SyncIntervalMinutes":10}""");
                }

                // 4-1. 디렉토리 보안 잠금 (일반 사용자의 임의 폴더 삭제/변조 차단)
                ApplyDirectoryHardening(_installDir);
                ApplyDirectoryHardening(_dataDir);

                // 5. Windows 서비스 등록
                Invoke(() => { _progressBar.Value = 70; _lblStatus.Text = "Windows 서비스 등록 중..."; });
                RunCmd("sc.exe", $"create {ServiceName} binPath= \"{targetExe}\" start= auto DisplayName= \"Angry Web Filter Service\"");
                RunCmd("sc.exe", $"description {ServiceName} \"웹 사이트 차단 및 집중 유지를 위한 Angry Web 보안 필터링 서비스\"");
                // 실패 시 0초만에 즉각 재시작 (강제 종료 방어)
                RunCmd("sc.exe", $"failure {ServiceName} reset= 0 actions= restart/1000/restart/1000/restart/1000");

                // 6. 서비스 시작
                Invoke(() => { _progressBar.Value = 85; _lblStatus.Text = "서비스 시작 중..."; });
                RunCmd("sc.exe", $"start {ServiceName}");

                // 6-1. 일반 사용자의 서비스 임의 중지(sc stop / net stop) 권한 차단 (Service DACL 적용)
                // SYSTEM(SY) 및 Administrators(BA)에게만 중지/제어 권한 부여
                RunCmd("sc.exe", $"sdset {ServiceName} \"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)\"");

                // 7. 시작 메뉴 바로가기 생성 (Windows 검색에서 Angry Web 앱으로 검색되도록 등록)
                Invoke(() => { _progressBar.Value = 95; _lblStatus.Text = "시작 메뉴 바로가기 등록 중..."; });
                CreateStartMenuShortcut(targetExe);

                Invoke(() =>
                {
                    _progressBar.Value = 100;
                    _lblStatus.Text = "설치가 성공적으로 완료되었습니다!";
                    MessageBox.Show("Angry Web이 성공적으로 설치되고 백그라운드에서 동작을 시작했습니다!\n\n이제 Windows 검색창에 'Angry Web'을 입력하여 대시보드를 바로 실행할 수 있습니다.", "설치 완료", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    CheckCurrentStatus();
                });
            }
            catch (Exception ex)
            {
                Invoke(() =>
                {
                    MessageBox.Show($"설치 중 오류가 발생했습니다:\n{ex.Message}", "오류", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    _lblStatus.Text = "설치 실패";
                });
            }
            finally
            {
                Invoke(() => SetUiEnabled(true));
            }
        });
    }

    private async void BtnUninstall_Click(object? sender, EventArgs e)
    {
        var inputPw = _txtPassword.Text.Trim();
        var configPath = Path.Combine(_dataDir, "config.json");
        string expectedPw = "angryweb";

        if (File.Exists(configPath))
        {
            try
            {
                var text = File.ReadAllText(configPath);
                var match = System.Text.RegularExpressions.Regex.Match(text, "\"MasterPasswordHash\":\\s*\"(.*?)\"");
                if (match.Success) expectedPw = match.Groups[1].Value;
            }
            catch { }
        }

        if (!VerifyPassword(expectedPw, inputPw))
        {
            MessageBox.Show("제거를 방지하기 위한 마스터 비밀번호가 올바르지 않습니다.", "인증 실패", MessageBoxButtons.OK, MessageBoxIcon.Stop);
            return;
        }

        if (MessageBox.Show("정말 Angry Web 서비스를 제거하시겠습니까?", "제거 확인", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
        {
            return;
        }

        SetUiEnabled(false);
        _lblStatus.Text = "서비스 제거 중...";

        await Task.Run(() =>
        {
            try
            {
                // 제거 전 디렉토리 잠금 해제
                RemoveDirectoryHardening(_installDir);
                RemoveDirectoryHardening(_dataDir);

                RunCmd("sc.exe", $"stop {ServiceName}");
                RunCmd("sc.exe", $"delete {ServiceName}");
                RemoveStartMenuShortcut();
                Thread.Sleep(1000);

                Invoke(() =>
                {
                    _progressBar.Value = 0;
                    _lblStatus.Text = "제거가 완료되었습니다.";
                    MessageBox.Show("Angry Web 서비스가 완전히 제거되었습니다.", "제거 완료", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    CheckCurrentStatus();
                });
            }
            catch (Exception ex)
            {
                Invoke(() => MessageBox.Show($"제거 중 오류: {ex.Message}", "오류", MessageBoxButtons.OK, MessageBoxIcon.Error));
            }
            finally
            {
                Invoke(() => SetUiEnabled(true));
            }
        });
    }

    private void SetUiEnabled(bool enabled)
    {
        _btnInstall.Enabled = enabled;
        _btnUninstall.Enabled = enabled;
        _txtPassword.Enabled = enabled;
    }

    private static void ExtractResource(string resourceName, string targetPath)
    {
        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream == null)
        {
            // Fallback: look for file in local directories if not embedded
            var localFallback = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AngryWeb.Service.exe");
            if (File.Exists(localFallback))
            {
                File.Copy(localFallback, targetPath, true);
                return;
            }
            throw new InvalidOperationException($"리소스 {resourceName}을 찾을 수 없습니다.");
        }

        using var fileStream = new FileStream(targetPath, FileMode.Create, FileAccess.Write);
        stream.CopyTo(fileStream);
    }

    private static void CreateStartMenuShortcut(string targetExe)
    {
        try
        {
            var installDir = Path.GetDirectoryName(targetExe) ?? @"C:\Program Files\AngryWeb";
            var iconPath = Path.Combine(installDir, "app.ico");
            IconGenerator.EnsureAppIcon(iconPath);

            // 1. 공용 시작 메뉴 및 현재 사용자 시작 메뉴 폴더 모두 등록
            var paths = new List<string>
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms)),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs))
            };

            // HKEY_USERS의 활성 사용자 프로필 경로에도 복사
            try
            {
                var userProfile = Environment.GetEnvironmentVariable("USERPROFILE");
                if (!string.IsNullOrEmpty(userProfile))
                {
                    var userStart = Path.Combine(userProfile, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs");
                    if (!paths.Contains(userStart, StringComparer.OrdinalIgnoreCase))
                        paths.Add(userStart);
                }
            }
            catch { }

            foreach (var dir in paths)
            {
                try
                {
                    if (!Directory.Exists(dir))
                        Directory.CreateDirectory(dir);

                    // .url 파일에 예쁜 방패 아이콘 경로 지정
                    var urlPath = Path.Combine(dir, "Angry Web.url");
                    var content = $"""
[InternetShortcut]
URL=http://127.0.0.1:8898/dashboard
IconIndex=0
IconFile={iconPath}
""";
                    File.WriteAllText(urlPath, content, Encoding.ASCII);

                    // WScript.Shell을 통한 .lnk 생성 (아이콘 및 대시보드 연결)
                    var lnkPath = Path.Combine(dir, "Angry Web.lnk");
                    var ps = $"""
$w = New-Object -ComObject WScript.Shell
$s = $w.CreateShortcut('{lnkPath}')
$s.TargetPath = 'cmd.exe'
$s.Arguments = '/c start http://127.0.0.1:8898/dashboard'
$s.Description = 'Angry Web 사이트 차단 및 관리 대시보드'
$s.IconLocation = '{iconPath},0'
$s.WindowStyle = 7
$s.Save()
""";
                    var tempFile = Path.Combine(Path.GetTempPath(), "mklink.ps1");
                    File.WriteAllText(tempFile, ps);
                    RunCmd("powershell.exe", $"-ExecutionPolicy Bypass -NoProfile -File \"{tempFile}\"");
                    try { File.Delete(tempFile); } catch { }
                }
                catch { }
            }
        }
        catch { }
    }

    private static void RemoveStartMenuShortcut()
    {
        try
        {
            var dirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms),
                Environment.GetFolderPath(Environment.SpecialFolder.Programs)
            };
            foreach (var dir in dirs)
            {
                var f1 = Path.Combine(dir, "Angry Web.url");
                var f2 = Path.Combine(dir, "Angry Web.lnk");
                if (File.Exists(f1)) try { File.Delete(f1); } catch { }
                if (File.Exists(f2)) try { File.Delete(f2); } catch { }
            }
        }
        catch { }
    }

    private static string HashPassword(string plainPassword)
    {
        if (string.IsNullOrEmpty(plainPassword)) return string.Empty;
        var salted = "ANGRY_WEB_SALT_" + plainPassword;
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(salted));
        return "sha256:" + Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static bool VerifyPassword(string storedHashOrPlain, string inputPassword)
    {
        if (string.IsNullOrEmpty(storedHashOrPlain)) return false;
        if (storedHashOrPlain.StartsWith("sha256:"))
        {
            var hashedInput = HashPassword(inputPassword);
            return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(storedHashOrPlain),
                Encoding.UTF8.GetBytes(hashedInput)
            );
        }
        return string.Equals(storedHashOrPlain, inputPassword, StringComparison.Ordinal);
    }

    private static void ApplyDirectoryHardening(string path)
    {
        try
        {
            if (!Directory.Exists(path)) return;

            // icacls 명령어로 SYSTEM 및 Administrators에게 모든 권한을 주고,
            // Users 및 Everyone에게는 삭제(D) 및 권한 변경 권한을 차단
            // 1. 소유권을 Administrators로 설정
            RunCmd("takeown.exe", $"/F \"{path}\" /A /R /D Y");
            // 2. 상속 재설정 및 Administrators/SYSTEM Full Control
            RunCmd("icacls.exe", $"\"{path}\" /reset /T /C");
            RunCmd("icacls.exe", $"\"{path}\" /grant:r \"*S-1-5-18\":(OI)(CI)F /grant:r \"*S-1-5-32-544\":(OI)(CI)F /T /C");
            // 3. 일반 사용자(Users: S-1-5-32-545)에게 읽기/실행만 부여하고 삭제(D, DE) 및 쓰기(WD, AD) 박탈
            RunCmd("icacls.exe", $"\"{path}\" /grant \"*S-1-5-32-545\":(OI)(CI)RX /deny \"*S-1-5-32-545\":(DE,DC) /T /C");
        }
        catch { }
    }

    private static void RemoveDirectoryHardening(string path)
    {
        try
        {
            if (!Directory.Exists(path)) return;
            RunCmd("takeown.exe", $"/F \"{path}\" /A /R /D Y");
            RunCmd("icacls.exe", $"\"{path}\" /reset /T /C");
            RunCmd("icacls.exe", $"\"{path}\" /grant \"*S-1-5-32-544\":(OI)(CI)F /grant \"*S-1-5-32-545\":(OI)(CI)F /T /C");
        }
        catch { }
    }

    private static string RunCmd(string exe, string args)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = args,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return "";
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);
            return output;
        }
        catch
        {
            return "";
        }
    }
}
