using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Threading;
using System.Windows.Forms;

namespace AntonVpn
{
    internal static class Program
    {
        internal static bool IsSetup { get { return Assembly.GetExecutingAssembly().GetManifestResourceNames().Contains("client.zip"); } }

        [STAThread]
        private static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            try
            {
                // A deterministic visual check renders only this form; it never installs or connects.
                if (args.Length == 2 && args[0] == "--render-preview")
                {
                    using (var form = new InstallerForm(false))
                    {
                        form.Show(); Application.DoEvents();
                        using (var bitmap = new Bitmap(form.Width, form.Height))
                        {
                            form.DrawToBitmap(bitmap, new Rectangle(0, 0, form.Width, form.Height));
                            bitmap.Save(Path.GetFullPath(args[1]), System.Drawing.Imaging.ImageFormat.Png);
                        }
                    }
                    return;
                }
                if (!Environment.Is64BitOperatingSystem || Environment.OSVersion.Version.Major < 10)
                    throw new InvalidOperationException("Для установки нужна 64-разрядная Windows 10 или Windows 11.");

                string expectedSid = Argument(args, "--owner-sid");
                string actualSid = WindowsIdentity.GetCurrent().User.Value;
                if (expectedSid != null && expectedSid != actualSid)
                    throw new InvalidOperationException("Открой установщик из учётной записи администратора, на которой будешь пользоваться VPN. Ввод данных другого администратора устанавливает программу в другой профиль Windows.");

                bool uninstall = args.Contains("--uninstall");
                bool settings = args.Contains("--settings");
                if (IsSetup || settings || uninstall)
                {
                    if (!WindowsIntegration.IsAdministrator())
                    {
                        string mode = uninstall ? "--uninstall " : settings ? "--settings " : "";
                        try
                        {
                            Process.Start(new ProcessStartInfo {
                                FileName = Assembly.GetExecutingAssembly().Location,
                                Arguments = mode + "--owner-sid " + actualSid,
                                Verb = "runas", UseShellExecute = true,
                                WorkingDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)
                            });
                        }
                        catch (Win32Exception e) { if (e.NativeErrorCode != 1223) throw; }
                        return;
                    }
                    bool created;
                    using (var mutex = new Mutex(true, "Local\\AntonVPNInstaller-" + actualSid, out created))
                    {
                        if (!created) throw new InvalidOperationException("Установка или настройка VPN уже открыта. Вернись к её окну.");
                        if (uninstall)
                        {
                            if (MessageBox.Show("Удалить «Мой VPN» и сохранённую личную ссылку с этого компьютера?", "Удаление VPN", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                            {
                                InstallService.Uninstall();
                                MessageBox.Show("Программа удалена. Можно закрыть это окно.", "Мой VPN", MessageBoxButtons.OK, MessageBoxIcon.Information);
                            }
                        }
                        else Application.Run(new InstallerForm(settings));
                    }
                }
                else
                {
                    if (!File.Exists(Path.Combine(Support.ClientDir, "v2rayN.exe")))
                        throw new InvalidOperationException("Не найдены файлы VPN. Скачай установщик и установи программу заново.");
                    if (!InstallService.Launch())
                        throw new InvalidOperationException("Не удалось запустить VPN. Открой «Настроить VPN» в меню «Пуск» или повтори установку.");
                }
            }
            catch (Exception e)
            {
                // Native error strings can contain private profile data: only curated messages leave the process.
                string message = e is ArgumentException || e is InvalidOperationException ? e.Message :
                    "Не удалось завершить действие. Закрой другой VPN и повтори. Если ошибка сохраняется, переустанови программу или обратись к Антону.";
                MessageBox.Show(message, "Мой VPN", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private static string Argument(string[] args, string key)
        {
            int index = Array.IndexOf(args, key);
            if (index < 0) return null;
            if (index + 1 >= args.Length) throw new ArgumentException("Не удалось определить пользователя Windows. Открой программу заново.");
            return args[index + 1];
        }
    }
}
