using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace AntonVpn
{
    internal static class ConnectionProbe
    {
        internal static int FreePort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start(); int port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop(); return port;
        }
        internal static Dictionary<string, object> Config(VlessLink link, int port)
        {
            if (link == null) throw new ArgumentNullException("link");
            if (port < 1 || port > 65535) throw new ArgumentOutOfRangeException("port");
            return Support.Obj("log", Support.Obj("disabled", true),
                "dns", Support.Obj("servers", new[] { Support.Obj("type", "local", "tag", "local") }, "final", "local"),
                "inbounds", new[] { Support.Obj("type", "mixed", "tag", "verify", "listen", "127.0.0.1", "listen_port", port) },
                "outbounds", new[] { link.Outbound() }, "route", Support.Obj("final", "proxy", "default_domain_resolver", "local"));
        }
        internal static void Verify(string clientDir, VlessLink link)
        {
            // An isolated proxy with no TUN or direct fallback verifies the actual personal credential.
            int port = FreePort();
            string temp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AntonVPN-Probes", Guid.NewGuid().ToString("N"));
            string configFile = Path.Combine(temp, "check.json");
            Process process = null;
            SecurityProtocolType previousTls = ServicePointManager.SecurityProtocol;
            try
            {
                WindowsIntegration.ProtectDirectory(temp);
                Support.WriteJson(configFile, Config(link, port));
                process = Process.Start(new ProcessStartInfo {
                    FileName = Path.Combine(clientDir, "bin", "sing_box", "sing-box.exe"),
                    Arguments = "run -c \"" + configFile + "\"", WorkingDirectory = clientDir,
                    UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true, RedirectStandardOutput = true
                });
                // Discard output: native errors can contain connection details.
                process.OutputDataReceived += delegate { }; process.ErrorDataReceived += delegate { };
                process.BeginOutputReadLine(); process.BeginErrorReadLine();
                bool ready = false;
                for (int i = 0; i < 50 && !process.HasExited; i++)
                {
                    try { using (var tcp = new TcpClient()) tcp.Connect(IPAddress.Loopback, port); ready = true; break; }
                    catch (SocketException) { Thread.Sleep(100); }
                }
                if (!ready) throw new InvalidOperationException("Не удалось запустить проверку VPN. Закрой другой VPN и повтори.");
                ServicePointManager.SecurityProtocol = previousTls | SecurityProtocolType.Tls12;
                for (int attempt = 0; attempt < 2; attempt++)
                {
                    try
                    {
                        var request = (HttpWebRequest)WebRequest.Create("https://www.cloudflare.com/cdn-cgi/trace");
                        request.Proxy = new WebProxy("http://127.0.0.1:" + port, false);
                        request.Timeout = 18000; request.ReadWriteTimeout = 18000; request.KeepAlive = false;
                        using (var response = (HttpWebResponse)request.GetResponse())
                        using (var reader = new StreamReader(response.GetResponseStream()))
                            if (response.StatusCode == HttpStatusCode.OK && reader.ReadToEnd().Contains("ip=")) return;
                    }
                    catch (WebException) { }
                }
                throw new InvalidOperationException("Сервер не подтвердил подключение. Проверь интернет и личную ссылку: доступ мог быть отключён или закончиться. Запроси актуальную ссылку у Антона.");
            }
            finally
            {
                ServicePointManager.SecurityProtocol = previousTls;
                if (process != null) { try { if (!process.HasExited) { process.Kill(); process.WaitForExit(5000); } } catch (InvalidOperationException) { } process.Dispose(); }
                // Only the dedicated private probe directory is removed, never the installation root.
                try { if (Directory.Exists(temp)) Directory.Delete(temp, true); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
        internal static bool WaitClient(string clientDir, int port)
        {
            return WaitClient(clientDir, port, true);
        }
        internal static bool WaitClient(string clientDir, int port, bool requireTun)
        {
            for (int i = 0; i < 80; i++)
            {
                // Core process path AND runtime TUN config must belong to this installation.
                if (WindowsIntegration.HasCore(clientDir) && HasRuntimeConfig(clientDir, port, requireTun))
                {
                    try { using (var tcp = new TcpClient()) tcp.Connect(IPAddress.Loopback, port); return true; }
                    catch (SocketException) { }
                }
                Thread.Sleep(250);
            }
            return false;
        }
        internal static bool HasRuntimeConfig(string clientDir, int port, bool requireTun)
        {
            try
            {
                string file = Path.Combine(clientDir, "binConfigs", "config.json");
                if (!File.Exists(file)) return false;
                var config = Support.Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(file));
                object raw;
                if (config == null || !config.TryGetValue("inbounds", out raw) || !(raw is IEnumerable)) return false;
                bool listener = false, tun = false;
                foreach (object item in (IEnumerable)raw)
                {
                    var inbound = item as Dictionary<string, object>;
                    if (inbound == null) continue;
                    object type, listenPort, autoRoute;
                    if (!inbound.TryGetValue("type", out type)) continue;
                    if ((string)type == "tun" && inbound.TryGetValue("auto_route", out autoRoute) && true.Equals(autoRoute)) tun = true;
                    if (((string)type == "mixed" || (string)type == "socks") && inbound.TryGetValue("listen_port", out listenPort) &&
                        Convert.ToInt32(listenPort) == port) listener = true;
                }
                return listener && (!requireTun || tun);
            }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
            catch (ArgumentException) { return false; }
            catch (InvalidOperationException) { return false; }
            catch (FormatException) { return false; }
            catch (InvalidCastException) { return false; }
            catch (OverflowException) { return false; }
        }
    }
}
