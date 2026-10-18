using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Security.Principal;
using System.Threading;

namespace AntonVpn
{
    internal static class InstallService
    {
        internal static void Install(string personalLink, bool autoRun, Action<int, string> progress)
        {
            Apply(personalLink, autoRun, progress, true);
        }

        internal static void Configure(string personalLink, bool autoRun, Action<int, string> progress)
        {
            Apply(personalLink, autoRun, progress, false);
        }

        private static void Apply(string personalLink, bool autoRun, Action<int, string> progress, bool installPayload)
        {
            VlessLink link = VlessLink.Parse(personalLink);
            if (progress == null) progress = delegate { };
            WindowsIntegration.RequireAdministrator();
            using (var installationLock = new InstallationLock())
            {
                WindowsIntegration.EnsureNoOtherVpn();
                WindowsIntegration.EnsureInstallRoot();
                WindowsIntegration.AssertNoReparsePoints(Support.InstallRoot);
                if (!installPayload && !File.Exists(Path.Combine(Support.ClientDir, "v2rayN.exe")))
                    throw new InvalidOperationException("Файлы клиента не найдены. Скачай и запусти полный установщик.");

                var integration = WindowsIntegration.CaptureIntegration();
                string token = Guid.NewGuid().ToString("N");
                string stage = Support.SafeChild(Support.InstallRoot, "stage-" + token);
                string previous = Support.SafeChild(Support.InstallRoot, "rollback-" + token);
                string helperBackup = Support.SafeChild(Support.InstallRoot, "helper-rollback-" + token);
                var helperNames = new[] { "AntonVPN.exe", "LICENSE.txt", "THIRD-PARTY.txt" };
                var movedHelpers = new List<string>();
                bool previousMoved = false, newClientMoved = false, integrationsChanged = false, helperChangeStarted = false, helperInstallStarted = false, licensesMoved = false;
                bool committed = false;
                try
                {
                    WindowsIntegration.ProtectDirectory(stage);
                    if (installPayload)
                    {
                        Package.Extract(stage, progress);
                        // Keep the user's profiles and application preferences while replacing packaged binaries.
                        string configs = Path.Combine(Support.ClientDir, "guiConfigs");
                        if (Directory.Exists(configs)) CopyTree(configs, Path.Combine(stage, "guiConfigs"));
                    }
                    else
                    {
                        progress(10, "Подготавливаю безопасную копию настроек…");
                        CopyTree(Support.ClientDir, stage);
                    }
                    if (!File.Exists(Path.Combine(stage, "v2rayN.exe")) || !File.Exists(Path.Combine(stage, "bin", "sing_box", "sing-box.exe")))
                        throw new InvalidOperationException("Не найдены обязательные файлы VPN. Скачай полный установщик заново.");

                    progress(45, "Проверяю личную ссылку подключения…");
                    ConnectionProbe.Verify(stage, link);
                    progress(65, "Сохраняю профиль и выборочные маршруты…");
                    ClientConfig.Write(stage, link, true, autoRun, ConnectionProbe.FreePort());

                    // Check again immediately before replacement: an autostart task may have run meanwhile.
                    WindowsIntegration.EnsureNoOtherVpn();
                    if (Directory.Exists(Support.ClientDir))
                    {
                        Directory.Move(Support.ClientDir, previous);
                        previousMoved = true;
                    }
                    Directory.Move(stage, Support.ClientDir);
                    newClientMoved = true;

                    if (installPayload)
                    {
                        WindowsIntegration.ProtectDirectory(helperBackup);
                        helperChangeStarted = true;
                        foreach (string name in helperNames)
                        {
                            string file = Path.Combine(Support.InstallRoot, name);
                            if (File.Exists(file))
                            {
                                // A running Windows executable can be renamed, but cannot be overwritten.
                                File.Move(file, Path.Combine(helperBackup, name));
                                movedHelpers.Add(name);
                            }
                        }
                        string licenses = Path.Combine(Support.InstallRoot, "licenses");
                        if (Directory.Exists(licenses))
                        {
                            Directory.Move(licenses, Path.Combine(helperBackup, "licenses"));
                            licensesMoved = true;
                        }
                        helperInstallStarted = true;
                        Package.InstallLauncher();
                    }
                    progress(85, "Добавляю ярлыки и запуск при входе…");
                    integrationsChanged = true;
                    WindowsIntegration.RegisterTask(autoRun);
                    WindowsIntegration.Shortcuts();
                    committed = true;
                }
                catch
                {
                    bool rollbackFailed = false;
                    if (integrationsChanged) TryRollback(delegate { WindowsIntegration.RestoreIntegration(integration); }, ref rollbackFailed);
                    if (helperChangeStarted)
                    {
                        foreach (string name in helperNames)
                        {
                            string capturedName = name;
                            TryRollback(delegate
                            {
                                string original = Path.Combine(Support.InstallRoot, capturedName);
                                if (movedHelpers.Contains(capturedName))
                                {
                                    if (File.Exists(original)) File.Delete(original);
                                    File.Move(Path.Combine(helperBackup, capturedName), original);
                                }
                                else if (helperInstallStarted && File.Exists(original)) File.Delete(original);
                            }, ref rollbackFailed);
                        }
                        if (licensesMoved || helperInstallStarted)
                            TryRollback(delegate
                            {
                                string licenses = Path.Combine(Support.InstallRoot, "licenses");
                                WindowsIntegration.DeleteOwnedChild(licenses);
                                if (licensesMoved) Directory.Move(Path.Combine(helperBackup, "licenses"), licenses);
                            }, ref rollbackFailed);
                    }
                    if (newClientMoved) TryRollback(delegate { WindowsIntegration.DeleteOwnedChild(Support.ClientDir); }, ref rollbackFailed);
                    if (previousMoved) TryRollback(delegate { Directory.Move(previous, Support.ClientDir); }, ref rollbackFailed);
                    TryRollback(delegate { WindowsIntegration.DeleteOwnedChild(stage); }, ref rollbackFailed);
                    if (!rollbackFailed) TryRollback(delegate { WindowsIntegration.DeleteOwnedChild(helperBackup); }, ref rollbackFailed);
                    if (rollbackFailed)
                        throw new InvalidOperationException("Настройка не завершена, восстановление предыдущей версии требует проверки. Резервные файлы сохранены в папке AntonVPN. Закрой программу и запусти полный установщик повторно; не удаляй папки rollback вручную.");
                    throw;
                }
                finally
                {
                    if (committed)
                    {
                        // Cleanup cannot invalidate a completed installation. Locked copies stay private until a later setup run.
                        BestEffortCleanup(previous);
                        BestEffortCleanup(helperBackup);
                        BestEffortCleanup(stage);
                    }
                }
                progress(100, "Готово. Личный профиль проверен.");
            }
        }

        private static void TryRollback(Action action, ref bool failed)
        {
            try { action(); } catch { failed = true; }
        }

        private static void BestEffortCleanup(string path)
        {
            try { WindowsIntegration.DeleteOwnedChild(path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }

        private static void CopyTree(string source, string destination)
        {
            WindowsIntegration.AssertNoReparsePoints(source);
            Directory.CreateDirectory(destination);
            foreach (string file in Directory.GetFiles(source)) File.Copy(file, Path.Combine(destination, Path.GetFileName(file)), true);
            foreach (string child in Directory.GetDirectories(source)) CopyTree(child, Path.Combine(destination, Path.GetFileName(child)));
        }

        internal static bool Launch()
        {
            using (var installationLock = new InstallationLock())
            {
                WindowsIntegration.AssertOwnedRoot();
                string configFile = Path.Combine(Support.ClientDir, "guiConfigs", "guiNConfig.json");
                if (!File.Exists(configFile)) throw new InvalidOperationException("Настройки VPN не найдены. Запусти установщик или открой «Настроить VPN».");
                int port = 0;
                try
                {
                    var config = Support.Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(configFile));
                    foreach (object inbound in (IEnumerable)config["Inbound"])
                    {
                        port = Convert.ToInt32(((Dictionary<string, object>)inbound)["LocalPort"]);
                        break;
                    }
                }
                catch (Exception e)
                {
                    if (!(e is ArgumentException) && !(e is InvalidOperationException) && !(e is InvalidCastException) && !(e is KeyNotFoundException) && !(e is FormatException) && !(e is OverflowException)) throw;
                }
                if (port < 1 || port > 65535) throw new InvalidOperationException("Не удалось прочитать настройки VPN. Открой «Настроить VPN» и сохрани личную ссылку повторно.");
                if (!WindowsIntegration.ClientRunning(Support.ClientDir))
                {
                    WindowsIntegration.EnsureNoOtherVpn();
                    if (!WindowsIntegration.StartTask()) return false;
                }
                return ConnectionProbe.WaitClient(Support.ClientDir, port, true);
            }
        }

        internal static void Uninstall()
        {
            using (var installationLock = new InstallationLock()) WindowsIntegration.Uninstall();
        }

        private sealed class InstallationLock : IDisposable
        {
            private readonly Mutex mutex;
            internal InstallationLock()
            {
                mutex = new Mutex(false, "Local\\AntonVPN-Install-" + WindowsIdentity.GetCurrent().User.Value);
                bool entered;
                try { entered = mutex.WaitOne(0); } catch (AbandonedMutexException) { entered = true; }
                if (!entered) { mutex.Dispose(); throw new InvalidOperationException("Другая настройка VPN уже выполняется. Дождись её завершения."); }
            }
            public void Dispose() { mutex.ReleaseMutex(); mutex.Dispose(); }
        }
    }
}
