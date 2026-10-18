using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;

namespace AntonVpn
{
    internal static class PayloadTests
    {
        private static int Main(string[] args)
        {
            try
            {
                string qa = Path.GetFullPath(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location));
                if (Path.GetFileName(qa) != ".qa") throw new InvalidOperationException("Tests must run inside .qa.");
                string destination = Support.SafeChild(qa, "payload");
                if (Directory.Exists(destination))
                {
                    WindowsIntegration.AssertNoReparsePoints(destination);
                    Directory.Delete(destination, true);
                }
                Directory.CreateDirectory(destination);
                Package.Extract(destination, delegate(int percent, string text) { });
                Assert(!Directory.Exists(Path.Combine(destination, "guiConfigs")), "official payload contains no user profile");
                Assert(!Directory.Exists(Path.Combine(destination, "guiTemps")), "official payload contains no generated config");
                Assert(FileVersionInfo.GetVersionInfo(Path.Combine(destination, "v2rayN.exe")).FileVersion.StartsWith("7.25.4"), "pinned client version");
                var start = new ProcessStartInfo {
                    FileName = Path.Combine(destination, "bin", "sing_box", "sing-box.exe"), Arguments = "version",
                    UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true
                };
                using (var process = Process.Start(start))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    Assert(process.ExitCode == 0 && output.StartsWith("sing-box version 1.14.0"), "pinned core version");
                }
                byte[] bytes;
                using (var stream = Support.Resource("launcher.exe"))
                using (var memory = new MemoryStream()) { stream.CopyTo(memory); bytes = memory.ToArray(); }
                Assert(bytes[0] == 'M' && bytes[1] == 'Z', "launcher PE header");
                var launcher = Assembly.ReflectionOnlyLoad(bytes);
                Assert(!launcher.GetManifestResourceNames().Contains("client.zip"), "installed launcher has no duplicate client payload");
                Assert(launcher.GetManifestResourceNames().Contains("routing.json"), "launcher has routing for settings changes");
                Console.WriteLine("PAYLOAD_TESTS_OK");
                return 0;
            }
            catch (Exception e) { Console.Error.WriteLine(e.GetType().Name + ": " + e.Message); return 1; }
        }

        private static void Assert(bool value, string label)
        {
            if (!value) throw new InvalidOperationException(label);
            Console.WriteLine("PASS " + label);
        }
    }
}
