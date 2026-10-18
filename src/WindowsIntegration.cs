using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace AntonVpn
{
    internal static class WindowsIntegration
    {
        private const string OwnerFile = ".anton-vpn-owner";
        private const string Product = "AntonVPN-per-user-v1";
        private const string UninstallKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\AntonVPN";

        internal static bool IsAdministrator()
        {
            return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        }
        internal static void ValidateOwnerSid(string expectedSid)
        {
            if (string.IsNullOrEmpty(expectedSid) || expectedSid != CurrentSid())
                throw new InvalidOperationException("Установка для другого пользователя запрещена. Войди в Windows под учётной записью администратора и запусти установщик из неё. Не вводи данные другой учётной записи в окне разрешения Windows.");
        }
        private static string CurrentSid() { return WindowsIdentity.GetCurrent().User.Value; }
        private static string MarkerText() { return Product + "\n" + CurrentSid(); }
        internal static void RequireAdministrator()
        {
            if (!IsAdministrator()) throw new InvalidOperationException("Для настройки VPN нужны права администратора. Запусти установщик повторно и разреши изменения Windows.");
        }
        internal static string TaskName()
        {
            // Match v2rayN's own per-user autostart identifier.
            string baseDir = Path.GetFullPath(Support.ClientDir).TrimEnd('\\') + "\\";
            using (var md5 = MD5.Create()) return "v2rayNAutoRun_" + BitConverter.ToString(md5.ComputeHash(Encoding.UTF8.GetBytes(baseDir))).Replace("-", "").ToLowerInvariant();
        }
        internal static void ProtectDirectory(string root)
        {
            Directory.CreateDirectory(root);
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            foreach (var sid in new[] { WindowsIdentity.GetCurrent().User, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) })
                security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(root).SetAccessControl(security);
        }
        internal static void ValidateInstallPath()
        {
            string local = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)).TrimEnd('\\');
            string expected = Path.Combine(local, "Programs", "AntonVPN");
            if (!string.Equals(Path.GetFullPath(Support.InstallRoot).TrimEnd('\\'), expected, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Не удалось проверить путь установки.");
            foreach (string path in new[] { local, Path.Combine(local, "Programs"), expected })
                if ((Directory.Exists(path) || File.Exists(path)) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException("Папка установки содержит перенаправление. Нужна обычная локальная папка профиля Windows.");
            if (File.Exists(expected)) throw new InvalidOperationException("Путь установки занят файлом.");
        }
        internal static void EnsureInstallRoot()
        {
            RequireAdministrator(); ValidateInstallPath();
            if (Directory.Exists(Support.InstallRoot))
            {
                string marker = Path.Combine(Support.InstallRoot, OwnerFile);
                if (File.Exists(marker)) AssertOwnedRoot();
                else if (Directory.GetFileSystemEntries(Support.InstallRoot).Length != 0)
                    throw new InvalidOperationException("Папка «AntonVPN» уже занята неизвестной установкой. Сохрани её под другим именем и повтори установку.");
            }
            ProtectDirectory(Support.InstallRoot);
            File.WriteAllText(Path.Combine(Support.InstallRoot, OwnerFile), MarkerText(), new UTF8Encoding(false));
        }
        internal static void AssertOwnedRoot()
        {
            ValidateInstallPath();
            string marker = Path.Combine(Support.InstallRoot, OwnerFile);
            if (!File.Exists(marker) || (File.GetAttributes(marker) & FileAttributes.ReparsePoint) != 0 || File.ReadAllText(marker) != MarkerText())
                throw new InvalidOperationException("Не удалось подтвердить владельца этой установки. Запусти исходный установщик в своей учётной записи Windows.");
        }
        internal static void AssertNoReparsePoints(string path)
        {
            if (!Directory.Exists(path) && !File.Exists(path)) return;
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Обнаружено перенаправление внутри папки VPN. Операция остановлена для защиты файлов.");
            if (Directory.Exists(path))
                foreach (string child in Directory.GetFileSystemEntries(path)) AssertNoReparsePoints(child);
        }
        internal static void DeleteOwnedChild(string path)
        {
            AssertOwnedRoot();
            string root = Path.GetFullPath(Support.InstallRoot).TrimEnd('\\') + "\\";
            string full = Path.GetFullPath(path).TrimEnd('\\');
            if (!full.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Недопустимый путь удаления.");
            AssertNoReparsePoints(full);
            if (Directory.Exists(full)) Directory.Delete(full, true);
            else if (File.Exists(full)) File.Delete(full);
        }
        private static bool ProcessRunning(string dir, string name, string relative)
        {
            string expected = Path.GetFullPath(Path.Combine(dir, relative));
            using (var query = new ManagementObjectSearcher("SELECT ExecutablePath FROM Win32_Process WHERE Name='" + name + "'"))
            using (var results = query.Get())
                foreach (ManagementObject process in results)
                    using (process)
                        if (string.Equals(process["ExecutablePath"] as string, expected, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }
        internal static bool HasCore(string dir) { return ProcessRunning(dir, "sing-box.exe", @"bin\sing_box\sing-box.exe"); }
        internal static bool ClientRunning(string dir) { return ProcessRunning(dir, "v2rayN.exe", "v2rayN.exe"); }
        internal static void EnsureNoOtherVpn()
        {
            foreach (string name in new[] { "v2rayN", "Hiddify", "hiddify", "HiddifyNext", "AdGuardVPN" })
            {
                var processes = Process.GetProcessesByName(name);
                bool found = processes.Length != 0;
                foreach (var process in processes) process.Dispose();
                if (found) throw new InvalidOperationException("Закрой другой VPN-клиент через его значок возле часов, затем нажми кнопку ещё раз. Для замены ссылки сначала выбери «Выход» в меню «Мой VPN».");
            }
            if (HasCore(Support.ClientDir)) throw new InvalidOperationException("Ядро VPN ещё работает. Закрой клиент через значок возле часов и повтори операцию.");
        }
        private static dynamic Scheduler()
        {
            dynamic service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service"));
            service.Connect(); return service;
        }
        private static dynamic ExistingTask(dynamic service)
        {
            try { return service.GetFolder("\\").GetTask(TaskName()); }
            catch (FileNotFoundException) { return null; }
            catch (COMException e) { if (e.ErrorCode == unchecked((int)0x80070002)) return null; throw; }
        }
        private static void AssertOurTask(dynamic registered)
        {
            dynamic definition = registered.Definition;
            string identity = definition.Principal.UserId;
            string sid;
            try { sid = identity.StartsWith("S-1-", StringComparison.Ordinal) ? identity : ((SecurityIdentifier)new NTAccount(identity).Translate(typeof(SecurityIdentifier))).Value; }
            catch (IdentityNotMappedException) { throw new InvalidOperationException("Задача запуска VPN принадлежит другой учётной записи."); }
            if (sid != CurrentSid() || definition.Actions.Count != 1)
                throw new InvalidOperationException("Задача запуска VPN принадлежит другой программе или учётной записи.");
            dynamic action = definition.Actions.Item(1);
            if (action.Type != 0 || !string.Equals((string)action.Path, Path.Combine(Support.ClientDir, "v2rayN.exe"), StringComparison.OrdinalIgnoreCase) || !string.IsNullOrEmpty((string)action.Arguments))
                throw new InvalidOperationException("Существующая задача запуска VPN имеет неизвестную команду. Настройка остановлена.");
        }
        internal static void RegisterTask(bool autoRun)
        {
            RequireAdministrator(); AssertOwnedRoot();
            dynamic service = Scheduler(); dynamic previous = ExistingTask(service);
            if (previous != null) AssertOurTask(previous);
            dynamic task = service.NewTask(0);
            string identity = CurrentSid();
            task.RegistrationInfo.Description = "Anton VPN: личный профиль и выборочные маршруты";
            task.Principal.UserId = identity; task.Principal.LogonType = 3; task.Principal.RunLevel = 1;
            task.Settings.DisallowStartIfOnBatteries = false; task.Settings.StopIfGoingOnBatteries = false;
            task.Settings.ExecutionTimeLimit = "PT0S"; task.Settings.MultipleInstances = 2;
            if (autoRun) { dynamic trigger = task.Triggers.Create(9); trigger.UserId = identity; trigger.Delay = "PT10S"; }
            dynamic action = task.Actions.Create(0);
            action.Path = Path.Combine(Support.ClientDir, "v2rayN.exe"); action.WorkingDirectory = Support.ClientDir;
            service.GetFolder("\\").RegisterTaskDefinition(TaskName(), task, 6, identity, null, 3, null);
        }
        internal static bool StartTask()
        {
            AssertOwnedRoot();
            try
            {
                dynamic service = Scheduler(); dynamic task = ExistingTask(service);
                if (task == null) return false;
                AssertOurTask(task); task.Run(null); return true;
            }
            catch (COMException) { return false; }
        }
        internal static void StartClient()
        {
            if (!StartTask()) throw new InvalidOperationException("Не удалось запустить VPN. Открой «Настроить VPN» и сохрани настройки повторно.");
        }
        private static void DeleteTask()
        {
            dynamic service = Scheduler(); dynamic task = ExistingTask(service);
            if (task != null) { AssertOurTask(task); service.GetFolder("\\").DeleteTask(TaskName(), 0); }
        }
        private static string ProgramsDirectory() { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), "Мой VPN"); }
        private static string[] ShortcutPaths()
        {
            return new[] { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Мой VPN.lnk"), Path.Combine(ProgramsDirectory(), "Мой VPN.lnk"), Path.Combine(ProgramsDirectory(), "Настроить VPN.lnk") };
        }
        private static void AssertOurShortcut(string path)
        {
            if (!File.Exists(path)) return;
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("Ярлык VPN содержит перенаправление.");
            dynamic shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell")); dynamic shortcut = shell.CreateShortcut(path);
            if (!string.Equals((string)shortcut.TargetPath, Path.Combine(Support.InstallRoot, "AntonVPN.exe"), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Ярлык «Мой VPN» уже используется другой программой. Переименуй его и повтори настройку.");
        }
        private static void AssertOurRegistry()
        {
            using (var key = Registry.CurrentUser.OpenSubKey(UninstallKey))
                if (key != null && !string.Equals(key.GetValue("InstallLocation") as string, Support.InstallRoot, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Запись удаления VPN уже используется другой установкой.");
        }
        internal static void Shortcuts()
        {
            AssertOwnedRoot(); AssertOurRegistry(); string programs = ProgramsDirectory();
            if (Directory.Exists(programs)) AssertNoReparsePoints(programs);
            foreach (string path in ShortcutPaths()) AssertOurShortcut(path);
            Directory.CreateDirectory(programs);
            dynamic shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell"));
            foreach (string path in ShortcutPaths())
            {
                dynamic shortcut = shell.CreateShortcut(path);
                shortcut.TargetPath = Path.Combine(Support.InstallRoot, "AntonVPN.exe");
                shortcut.Arguments = path == Path.Combine(programs, "Настроить VPN.lnk") ? "--settings" : "";
                shortcut.WorkingDirectory = Support.InstallRoot; shortcut.Description = "Мой VPN"; shortcut.Save();
            }
            using (var key = Registry.CurrentUser.CreateSubKey(UninstallKey))
            {
                key.SetValue("DisplayName", "Мой VPN"); key.SetValue("DisplayVersion", Support.Version);
                key.SetValue("Publisher", "UiminAA"); key.SetValue("InstallLocation", Support.InstallRoot);
                key.SetValue("UninstallString", "\"" + Path.Combine(Support.InstallRoot, "AntonVPN.exe") + "\" --uninstall");
                key.SetValue("NoModify", 1, RegistryValueKind.DWord); key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
            }
        }
        internal sealed class IntegrationBackup
        {
            internal string TaskXml;
            internal Dictionary<string, byte[]> Shortcuts = new Dictionary<string, byte[]>();
            internal Dictionary<string, object> RegistryValues;
            internal Dictionary<string, RegistryValueKind> RegistryKinds = new Dictionary<string, RegistryValueKind>();
        }
        internal static IntegrationBackup CaptureIntegration()
        {
            var backup = new IntegrationBackup(); dynamic service = Scheduler(); dynamic task = ExistingTask(service);
            if (task != null) { AssertOurTask(task); backup.TaskXml = task.Xml; }
            if (Directory.Exists(ProgramsDirectory())) AssertNoReparsePoints(ProgramsDirectory());
            foreach (string path in ShortcutPaths()) { AssertOurShortcut(path); backup.Shortcuts[path] = File.Exists(path) ? File.ReadAllBytes(path) : null; }
            AssertOurRegistry();
            using (var key = Registry.CurrentUser.OpenSubKey(UninstallKey))
                if (key != null)
                {
                    if (key.GetSubKeyNames().Length != 0) throw new InvalidOperationException("Запись удаления VPN имеет неизвестные вложенные настройки.");
                    backup.RegistryValues = new Dictionary<string, object>();
                    foreach (string name in key.GetValueNames()) { backup.RegistryValues[name] = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames); backup.RegistryKinds[name] = key.GetValueKind(name); }
                }
            return backup;
        }
        internal static void RestoreIntegration(IntegrationBackup backup)
        {
            if (backup.TaskXml == null) DeleteTask();
            else { dynamic service = Scheduler(); service.GetFolder("\\").RegisterTask(TaskName(), backup.TaskXml, 6, CurrentSid(), null, 3, null); }
            foreach (var item in backup.Shortcuts)
                if (item.Value == null) { if (File.Exists(item.Key)) { AssertOurShortcut(item.Key); File.Delete(item.Key); } }
                else { Directory.CreateDirectory(Path.GetDirectoryName(item.Key)); File.WriteAllBytes(item.Key, item.Value); }
            if (Directory.Exists(ProgramsDirectory()) && Directory.GetFileSystemEntries(ProgramsDirectory()).Length == 0) Directory.Delete(ProgramsDirectory());
            AssertOurRegistry(); Registry.CurrentUser.DeleteSubKeyTree(UninstallKey, false);
            if (backup.RegistryValues != null)
                using (var key = Registry.CurrentUser.CreateSubKey(UninstallKey))
                    foreach (var item in backup.RegistryValues) key.SetValue(item.Key, item.Value, backup.RegistryKinds[item.Key]);
        }
        internal static void Uninstall()
        {
            RequireAdministrator(); AssertOwnedRoot(); AssertNoReparsePoints(Support.InstallRoot);
            if (ClientRunning(Support.ClientDir) || HasCore(Support.ClientDir))
                throw new InvalidOperationException("Сначала выбери «Выход» в меню VPN возле часов, затем повтори удаление.");
            var integration = CaptureIntegration();
            try
            {
                DeleteTask();
                foreach (string path in ShortcutPaths()) { AssertOurShortcut(path); if (File.Exists(path)) File.Delete(path); }
                if (Directory.Exists(ProgramsDirectory()) && Directory.GetFileSystemEntries(ProgramsDirectory()).Length == 0) Directory.Delete(ProgramsDirectory());
                AssertOurRegistry(); Registry.CurrentUser.DeleteSubKeyTree(UninstallKey, false);
                string system = Environment.GetFolderPath(Environment.SpecialFolder.System);
                using (var helper = Process.Start(new ProcessStartInfo {
                    FileName = Path.Combine(system, @"WindowsPowerShell\v1.0\powershell.exe"),
                    Arguments = "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(UninstallScript(Process.GetCurrentProcess().Id))),
                    WorkingDirectory = system, UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden
                }))
                    if (helper == null) throw new InvalidOperationException("Не удалось запустить удаление VPN. Повтори удаление.");
            }
            catch
            {
                RestoreIntegration(integration);
                throw;
            }
        }

        internal static string UninstallScript(int processId)
        {
            // Recheck the fixed target, owner and reparse points after the running helper exits.
            string root = Path.GetFullPath(Support.InstallRoot).TrimEnd('\\');
            return "$ErrorActionPreference='Stop'; Wait-Process -Id " + processId + " -ErrorAction SilentlyContinue; " +
                "$target='" + root.Replace("'", "''") + "'; $expected=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Programs\\AntonVPN'; " +
                "if ([IO.Path]::GetFullPath($target).TrimEnd('\\') -ne [IO.Path]::GetFullPath($expected).TrimEnd('\\')) { exit 3 }; " +
                "foreach ($parent in @((Split-Path -Parent $target),([Environment]::GetFolderPath('LocalApplicationData')))) { if (((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { exit 5 } }; " +
                "function Assert-Tree([string]$directory) { $node=Get-Item -LiteralPath $directory -Force; if (($node.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { exit 5 }; " +
                "foreach ($child in Get-ChildItem -LiteralPath $directory -Force) { if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { exit 5 }; if ($child.PSIsContainer) { Assert-Tree $child.FullName } } }; Assert-Tree $target; " +
                "if ((Get-Content -LiteralPath (Join-Path $target '" + OwnerFile + "') -Raw) -ne '" + MarkerText().Replace("'", "''") + "') { exit 4 }; " +
                "Remove-Item -LiteralPath $target -Recurse -Force";
        }
    }
}
