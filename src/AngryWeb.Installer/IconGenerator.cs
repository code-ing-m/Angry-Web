using System.Drawing;
using System.Drawing.Drawing2D;

namespace AngryWeb.Installer;

public static class IconGenerator
{
    public static void EnsureAppIcon(string icoPath)
    {
        try
        {
            if (File.Exists(icoPath)) return;

            using var bmp = new Bitmap(64, 64);
            using (var g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;

                // 빨간 방패 배경
                using var brush = new SolidBrush(Color.FromArgb(248, 81, 73));
                var points = new Point[]
                {
                    new(32, 4),
                    new(58, 14),
                    new(58, 38),
                    new(32, 60),
                    new(6, 38),
                    new(6, 14)
                };
                g.FillPolygon(brush, points);

                // 흰색 외곽 테두리
                using var pen = new Pen(Color.White, 3);
                g.DrawPolygon(pen, points);

                // 가운데 느낌표 (!)
                using var font = new Font("Segoe UI", 24, FontStyle.Bold);
                using var sf = new StringFormat
                {
                    Alignment = StringAlignment.Center,
                    LineAlignment = StringAlignment.Center
                };
                g.DrawString("!", font, Brushes.White, new RectangleF(0, 0, 64, 64), sf);
            }

            using var icon = Icon.FromHandle(bmp.GetHicon());
            using var fs = new FileStream(icoPath, FileMode.Create);
            icon.Save(fs);
        }
        catch { }
    }
}

