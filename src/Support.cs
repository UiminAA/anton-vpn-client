using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace AntonVpn
{
    internal static class Support
    {
        internal const string Version = "1.0.0";
        internal const string ProfileId = "anton-vpn-user";
        internal const string RoutingId = "anton-vpn-selected";
        internal static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 8 * 1024 * 1024 };
        internal static string InstallRoot { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "AntonVPN"); } }
        internal static string ClientDir { get { return Path.Combine(InstallRoot, "client"); } }
        internal static Dictionary<string, object> Obj(params object[] pairs)
        {
            var result = new Dictionary<string, object>();
            for (int i = 0; i < pairs.Length; i += 2) result.Add((string)pairs[i], pairs[i + 1]);
            return result;
        }
        internal static Stream Resource(string name)
        {
            var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name);
            if (stream == null) throw new InvalidOperationException("Не найден файл программы. Скачай установщик заново.");
            return stream;
        }
        internal static string ResourceText(string name)
        {
            using (var stream = Resource(name)) using (var reader = new StreamReader(stream, Encoding.UTF8)) return reader.ReadToEnd();
        }
        internal static void WriteJson(string file, object value)
        {
            string temporary = file + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                File.WriteAllText(temporary, Json.Serialize(value), new UTF8Encoding(false));
                if (File.Exists(file)) File.Replace(temporary, file, null);
                else File.Move(temporary, file);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
        internal static string Hash(Stream stream)
        {
            using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
        }
        internal static string SafeChild(string root, string relative)
        {
            if (string.IsNullOrEmpty(relative) || Path.IsPathRooted(relative) || relative.Any(char.IsControl) ||
                relative.Split('/', '\\').Any(part => part == "." || part == ".." || part.EndsWith(".") || part.EndsWith(" ") ||
                    part.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0))
                throw new InvalidOperationException("Недопустимый путь файла.");
            string fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            string full = Path.GetFullPath(Path.Combine(fullRoot, relative));
            if (!full.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Недопустимый путь файла.");
            return full;
        }
    }

    internal sealed class VlessLink
    {
        internal string Server, Uuid, PublicKey, Sni, ShortId, Fingerprint, Flow, SpiderX, Alpn;
        internal int Port;
        internal static VlessLink Parse(string input)
        {
            // Never put the original URI in exceptions, process arguments, telemetry or logs.
            string text = (input ?? "").Trim();
            if (text.Length > 8192 || text.Any(char.IsWhiteSpace) || text.Any(char.IsControl)) throw new ArgumentException("Вставь одну полную ссылку vless:// из панели.");
            Uri uri;
            if (!Uri.TryCreate(text, UriKind.Absolute, out uri) || uri.Scheme != "vless" || string.IsNullOrEmpty(uri.Host))
                throw new ArgumentException("Нужна личная ссылка vless://, которую выдал Антон.");
            if ((uri.AbsolutePath != "" && uri.AbsolutePath != "/") || uri.HostNameType == UriHostNameType.Unknown)
                throw new ArgumentException("Ссылка повреждена. Скопируй её заново из панели.");
            Guid uuid;
            string user = Uri.UnescapeDataString(uri.UserInfo);
            if (user.Any(char.IsControl) || user.Any(char.IsWhiteSpace) || !Guid.TryParseExact(user, "D", out uuid) || uuid == Guid.Empty)
                throw new ArgumentException("В ссылке отсутствует корректный ключ пользователя.");
            var q = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string part in uri.Query.TrimStart('?').Split('&'))
            {
                if (part.Length == 0) continue;
                string[] pair = part.Split(new[] { '=' }, 2);
                string key = Uri.UnescapeDataString(pair[0]);
                string value = pair.Length == 2 ? Uri.UnescapeDataString(pair[1]) : "";
                if (key.Any(char.IsControl) || value.Any(char.IsControl) || q.ContainsKey(key)) throw new ArgumentException("Ссылка повреждена. Скопируй её заново из панели.");
                q.Add(key, value);
            }
            Func<string, string> get = delegate(string key) { return q.ContainsKey(key) ? q[key] : ""; };
            if (get("security") != "reality" || (get("type") != "tcp" && get("type") != "raw"))
                throw new ArgumentException("Этот установщик принимает VLESS + Reality (TCP) из панели Антона.");
            if ((get("encryption") != "" && get("encryption") != "none") ||
                (get("headerType") != "" && get("headerType") != "none") ||
                (get("allowInsecure") != "" && get("allowInsecure") != "0" && get("allowInsecure") != "false"))
                throw new ArgumentException("В ссылке указан неподдерживаемый режим подключения.");
            string pk = get("pbk"), sid = get("sid"), sni = get("sni"), flow = get("flow"), fp = get("fp");
            if (!System.Text.RegularExpressions.Regex.IsMatch(pk, "^[A-Za-z0-9_-]{43}$") ||
                !System.Text.RegularExpressions.Regex.IsMatch(sid, "^(?:[A-Fa-f0-9]{2}){0,8}$") ||
                Uri.CheckHostName(sni) != UriHostNameType.Dns || flow != "xtls-rprx-vision")
                throw new ArgumentException("В ссылке не хватает параметров Reality. Запроси полную ссылку подключения.");
            string[] fingerprints = { "chrome", "firefox", "edge", "safari", "ios", "android", "random", "randomized" };
            if (fp.Length == 0) fp = "chrome";
            if (!fingerprints.Contains(fp)) throw new ArgumentException("В ссылке указан неподдерживаемый TLS-профиль.");
            string alpn = get("alpn");
            if (alpn != "" && alpn.Split(',').Any(value => value != "h2" && value != "http/1.1" && value != "h3"))
                throw new ArgumentException("В ссылке указан неподдерживаемый TLS-протокол.");
            int port = uri.Port < 0 ? 443 : uri.Port;
            if (port < 1 || port > 65535) throw new ArgumentException("В ссылке указан неверный порт.");
            string server = uri.DnsSafeHost;
            System.Net.IPAddress address;
            if (System.Net.IPAddress.TryParse(server, out address)) server = address.ToString();
            return new VlessLink { Server = server, Port = port, Uuid = uuid.ToString(), PublicKey = pk,
                ShortId = sid, Sni = sni, Flow = flow, Fingerprint = fp, SpiderX = get("spx"), Alpn = alpn };
        }
        internal Dictionary<string, object> Outbound()
        {
            var tls = Support.Obj("enabled", true, "server_name", Sni,
                "utls", Support.Obj("enabled", true, "fingerprint", Fingerprint),
                "reality", Support.Obj("enabled", true, "public_key", PublicKey, "short_id", ShortId));
            if (!string.IsNullOrEmpty(Alpn)) tls.Add("alpn", Alpn.Split(','));
            return Support.Obj("type", "vless", "tag", "proxy", "server", Server, "server_port", Port,
                "uuid", Uuid, "flow", Flow, "tls", tls);
        }
    }
}
