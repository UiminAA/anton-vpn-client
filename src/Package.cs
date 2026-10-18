using System;
using System.IO;
using System.IO.Compression;
using System.Reflection;

namespace AntonVpn
{
    internal static class Package
    {
        internal static void Extract(string destination, Action<int, string> progress)
        {
            Directory.CreateDirectory(destination);
            using (var resource = Support.Resource("client.zip"))
            {
                progress(5, "Проверяю файлы установщика…");
                if (Support.Hash(resource) != Support.ResourceText("client.sha256").Trim())
                    throw new InvalidOperationException("Установщик повреждён. Скачай файл заново.");
                resource.Position = 0;
                using (var zip = new ZipArchive(resource, ZipArchiveMode.Read))
                {
                    int index = 0;
                    const string prefix = "v2rayN-windows-64/";
                    foreach (var entry in zip.Entries)
                    {
                        if (!entry.FullName.StartsWith(prefix, StringComparison.Ordinal))
                            throw new InvalidOperationException("Неверный состав файлов клиента. Скачай установщик заново.");
                        string relative = entry.FullName.Substring(prefix.Length);
                        if (relative.Length == 0) continue;
                        string file = Support.SafeChild(destination, relative);
                        if (entry.FullName.EndsWith("/")) { Directory.CreateDirectory(file); continue; }
                        Directory.CreateDirectory(Path.GetDirectoryName(file));
                        using (var input = entry.Open()) using (var output = File.Create(file)) input.CopyTo(output);
                        progress(10 + (++index * 30 / zip.Entries.Count), "Устанавливаю VPN-клиент…");
                    }
                    foreach (string name in new[] { "v2rayN.exe", "e_sqlite3.dll", "bin/sing_box/sing-box.exe" })
                        if (!File.Exists(Support.SafeChild(destination, name)))
                            throw new InvalidOperationException("Не хватает файлов клиента. Скачай установщик заново.");
                }
            }
        }
        internal static void InstallLauncher()
        {
            string file = Path.Combine(Support.InstallRoot, "AntonVPN.exe");
            using (var input = Support.Resource("launcher.exe")) using (var output = File.Create(file)) input.CopyTo(output);
            File.WriteAllText(Path.Combine(Support.InstallRoot, "LICENSE.txt"), Support.ResourceText("LICENSE.txt"));
            File.WriteAllText(Path.Combine(Support.InstallRoot, "THIRD-PARTY.txt"), Support.ResourceText("THIRD-PARTY.txt"));
            string licenses = Path.Combine(Support.InstallRoot, "licenses");
            Directory.CreateDirectory(licenses);
            using (var input = Support.Resource("licenses.zip"))
            using (var zip = new ZipArchive(input, ZipArchiveMode.Read))
                foreach (var entry in zip.Entries)
                {
                    string path = Support.SafeChild(licenses, entry.FullName);
                    Directory.CreateDirectory(Path.GetDirectoryName(path));
                    using (var source = entry.Open()) using (var output = File.Create(path)) source.CopyTo(output);
                }
        }
    }
}
