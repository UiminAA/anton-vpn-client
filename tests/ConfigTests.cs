using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace AntonVpn
{
    internal static class ConfigTests
    {
        private static int assertions;
        private static readonly string Example = "vless://11111111-2222-4333-8444-555555555555@example.invalid:443?encryption=none&security=reality&type=tcp&pbk=" +
            new string('A', 43) + "&sid=0123456789abcdef&sni=example.com&flow=xtls-rprx-vision&fp=chrome&spx=%2F";
        private static void Assert(bool condition, string name)
        {
            assertions++;
            if (!condition) throw new InvalidOperationException("Assertion failed: " + name);
        }
        private static void Reject(Action action, string name)
        {
            bool rejected = false;
            try { action(); }
            catch (ArgumentException) { rejected = true; }
            catch (InvalidOperationException) { rejected = true; }
            Assert(rejected, name);
        }
        private static Dictionary<string, object> Obj(object value) { return (Dictionary<string, object>)value; }
        private static IEnumerable<Dictionary<string, object>> Objects(object value)
        {
            foreach (object item in (IEnumerable)value) yield return Obj(item);
        }
        private static string[] Strings(object value) { return ((IEnumerable)value).Cast<object>().Select(item => (string)item).ToArray(); }
        private static void ParseTests()
        {
            var link = VlessLink.Parse("  " + Example + "\r\n");
            Assert(link.Server == "example.invalid" && link.Port == 443 && link.SpiderX == "/", "ordinary link and escaped spider path");
            Assert(VlessLink.Parse(Example.Replace(":443?", "?bar=baz&")).Port == 443, "default port");
            Assert(VlessLink.Parse(Example.Replace("type=tcp", "type=raw")).Flow == "xtls-rprx-vision", "raw alias");
            Assert(VlessLink.Parse(Example.Replace("example.invalid", "[2001:db8::1]")).Server == "2001:db8::1", "IPv6 literal strips brackets");
            Assert(VlessLink.Parse(Example.Replace("&fp=chrome", "")).Fingerprint == "chrome", "default fingerprint");
            Assert(VlessLink.Parse(Example.Replace("sid=0123456789abcdef", "sid=")).ShortId == "", "empty short id allowed");
            var alpn = VlessLink.Parse(Example + "&alpn=h2%2Chttp%2F1.1");
            Assert(Strings(Obj(alpn.Outbound()["tls"])["alpn"]).SequenceEqual(new[] { "h2", "http/1.1" }), "ALPN retained");
            foreach (string bad in new[] {
                "", "https://example.com", Example.Replace("vless://", "vmess://"),
                Example.Replace("11111111-2222-4333-8444-555555555555", "00000000-0000-0000-0000-000000000000"),
                Example.Replace("@example", "%0a@example"), Example + "&Security=reality", Example + "&x=%0d%0a",
                Example.Replace("type=tcp", "type=ws"), Example.Replace("security=reality", "security=tls"),
                Example.Replace("flow=xtls-rprx-vision", "flow="), Example.Replace("sid=0123456789abcdef", "sid=abc"),
                Example.Replace(new string('A', 43), new string('A', 42)), Example.Replace("sni=example.com", "sni=127.0.0.1"),
                Example.Replace("fp=chrome", "fp=unsupported"), Example.Replace("encryption=none", "encryption=aes"),
                Example + "&allowInsecure=1", Example + "&headerType=http", Example + "&alpn=not-a-protocol",
                Example.Replace("example.invalid:443?", "example.invalid:443/path?"), Example + "&x=two links"
            })
            {
                try { VlessLink.Parse(bad); Assert(false, "invalid VLESS input rejected"); }
                catch (ArgumentException error)
                {
                    Assert(!error.Message.Contains("11111111") && !error.Message.Contains("pbk="), "exception excludes connection material");
                }
            }
        }
        private static void RoutingTests()
        {
            var rules = ClientConfig.Rules().Select(Obj).ToArray();
            Assert(rules.Length >= 7, "service rules loaded");
            Assert(rules.Select(rule => (string)rule["Id"]).Distinct().Count() == rules.Length, "unique rule ids");
            Assert((string)rules.Last()["OutboundTag"] == "direct" && (string)rules.Last()["Network"] == "tcp,udp", "direct catch-all last");
            var domains = rules.Where(rule => rule.ContainsKey("Domain")).SelectMany(rule => Strings(rule["Domain"])).ToArray();
            foreach (string domain in new[] { "domain:chatgpt.com", "domain:openai.com", "domain:claude.ai", "domain:youtube.com", "domain:googlevideo.com", "domain:instagram.com", "domain:telegram.org", "full:youtubei.googleapis.com" })
                Assert(domains.Contains(domain), "required service: " + domain);
            Assert(!domains.Contains("domain:google.com") && !domains.Contains("domain:googleapis.com"), "general Google remains direct");
            var processes = rules.Where(rule => rule.ContainsKey("Process")).SelectMany(rule => Strings(rule["Process"])).ToArray();
            Assert(processes.Contains("Telegram.exe") && processes.Contains("ChatGPT.exe"), "desktop processes included");
            Assert(rules.Take(rules.Length - 1).All(rule => (string)rule["OutboundTag"] == "proxy"), "only explicit services proxy");
            var probe = ConnectionProbe.Config(VlessLink.Parse(Example), 23456);
            Assert((string)Obj(probe["route"])["final"] == "proxy", "probe has proxy-only default");
            Assert(Objects(probe["outbounds"]).Count() == 1 && (string)Objects(probe["outbounds"]).Single()["type"] == "vless", "probe has no direct fallback");
            Assert(Objects(probe["inbounds"]).All(item => (string)item["type"] != "tun"), "probe never creates TUN");
        }
        private static void PathAndJsonTests(string root)
        {
            Assert(Support.SafeChild(root, "sub/file.txt") == Path.Combine(root, "sub", "file.txt"), "archive child path");
            foreach (string bad in new[] { "../escape", "a/../../escape", "C:\\escape", "file:stream", "trailing.", "folder /file", "\\\\server\\share\\file" })
                Reject(delegate { Support.SafeChild(root, bad); }, "unsafe archive child rejected");
            string file = Path.Combine(root, "atomic.json");
            Support.WriteJson(file, Support.Obj("unicode", "Тест"));
            Support.WriteJson(file, Support.Obj("unicode", "Обновлено"));
            Assert((string)Support.Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(file))["unicode"] == "Обновлено", "atomic JSON replacement");
            Assert(Directory.GetFiles(root, "*.tmp").Length == 0, "temporary JSON files removed");
        }
        private static void RuntimeTests(string root)
        {
            string dir = Path.Combine(root, "runtime"); Directory.CreateDirectory(Path.Combine(dir, "binConfigs"));
            string file = Path.Combine(dir, "binConfigs", "config.json");
            Assert(!ConnectionProbe.HasRuntimeConfig(dir, 23456, true), "missing runtime config rejected");
            Support.WriteJson(file, Support.Obj("inbounds", new[] { Support.Obj("type", "mixed", "listen_port", 23456) }));
            Assert(!ConnectionProbe.HasRuntimeConfig(dir, 23456, true), "TUN required");
            Assert(ConnectionProbe.HasRuntimeConfig(dir, 23456, false), "optional proxy-only runtime accepted");
            Support.WriteJson(file, Support.Obj("inbounds", new[] { Support.Obj("type", "mixed", "listen_port", 23456), Support.Obj("type", "tun", "auto_route", true) }));
            Assert(ConnectionProbe.HasRuntimeConfig(dir, 23456, true), "TUN and configured port accepted");
            Assert(!ConnectionProbe.HasRuntimeConfig(dir, 23457, true), "different listener port rejected");
            File.WriteAllText(file, "{invalid");
            Assert(!ConnectionProbe.HasRuntimeConfig(dir, 23456, true), "partial config rejected during client startup");
        }
        private static void DatabaseTests(string root, string payload)
        {
            string dir = Path.Combine(root, "client"); Directory.CreateDirectory(dir);
            File.Copy(Path.Combine(payload, "e_sqlite3.dll"), Path.Combine(dir, "e_sqlite3.dll"));
            var link = VlessLink.Parse(Example + "&alpn=h2%2Chttp%2F1.1");
            ClientConfig.Write(dir, link, true, true, 23456);
            string jsonFile = Path.Combine(dir, "guiConfigs", "guiNConfig.json");
            var json = Support.Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(jsonFile));
            Assert((string)json["IndexId"] == Support.ProfileId, "active profile selected");
            Assert(true.Equals(Obj(json["TunModeItem"])["EnableTun"]), "TUN enabled");
            Assert((int)Obj(json["SystemProxyItem"])["SysProxyType"] == 2, "unrelated system proxy unchanged");
            Assert((string)Obj(json["SimpleDNSItem"])["DirectDNS"] == "localhost", "direct DNS uses system resolver");
            Assert((int)Objects(json["CoreTypeItem"]).Single()["CoreType"] == 24, "sing-box selected");
            using (var db = new NativeDatabase(dir))
            {
                Assert(db.Scalar("SELECT COUNT(*) FROM ProfileItem;") == "1", "one personal profile");
                Assert(db.Scalar("SELECT Password FROM ProfileItem;") == link.Uuid, "personal credential persisted");
                Assert(db.Scalar("SELECT Alpn FROM ProfileItem;") == "h2,http/1.1", "profile ALPN persisted");
                Assert(db.Scalar("SELECT CoreType FROM ProfileItem;") == "24", "profile core matches GUI");
                Assert((string)Support.Json.Deserialize<Dictionary<string, object>>(db.Scalar("SELECT ProtoExtra FROM ProfileItem;"))["Flow"] == "xtls-rprx-vision", "7.25.4 Flow field");
                var rules = Objects(Support.Json.DeserializeObject(db.Scalar("SELECT RuleSet FROM RoutingItem;"))).ToArray();
                Assert((string)rules.Last()["OutboundTag"] == "direct", "stored routes preserve catch-all");
                db.Exec("CREATE TABLE BindingTest (Id varchar PRIMARY KEY, Value varchar, Flag integer, Amount float, Big integer, Optional varchar);");
                string quoted = "Русский ' текст; DROP TABLE ProfileItem; --";
                db.Upsert("BindingTest", Support.Obj("Id", "1", "Value", quoted, "Flag", true, "Amount", 1.25, "Big", 2147483648L, "Optional", null));
                Assert(db.Scalar("SELECT Value FROM BindingTest;") == quoted, "UTF8 and SQL value binding");
                Assert(db.Scalar("SELECT Flag FROM BindingTest;") == "1" && db.Scalar("SELECT Amount FROM BindingTest;") == "1.25" && db.Scalar("SELECT Big FROM BindingTest;") == "2147483648", "typed SQLite binding");
                Assert(db.Scalar("SELECT Optional FROM BindingTest;") == null, "SQL NULL binding");
                db.Upsert("BindingTest", Support.Obj("Id", "empty", "Value", ""));
                Assert(db.Scalar("SELECT Value FROM BindingTest WHERE Id='empty';") == "", "empty strings remain distinct from SQL NULL");
                Reject(delegate { db.Upsert("Bad; DROP TABLE ProfileItem", Support.Obj("Id", "1")); }, "SQL identifiers validated");
                db.Upsert("RoutingItem", Support.Obj("Id", "unrelated", "Remarks", "keep", "IsActive", 1));
                db.Exec("BEGIN IMMEDIATE;"); db.Upsert("BindingTest", Support.Obj("Id", "rollback", "Value", "discard")); db.Exec("ROLLBACK;");
                Assert(db.Scalar("SELECT COUNT(*) FROM BindingTest WHERE Id='rollback';") == "0", "transaction rollback");
            }
            ClientConfig.Write(dir, link, true, false, 23457);
            using (var db = new NativeDatabase(dir))
            {
                Assert(db.Scalar("SELECT COUNT(*) FROM ProfileItem;") == "1", "reconfigure does not duplicate profile");
                Assert(db.Scalar("SELECT COUNT(*) FROM RoutingItem WHERE IsActive=1;") == "1", "one active route set after reconfigure");
                Assert(db.Scalar("SELECT Remarks FROM RoutingItem WHERE Id='unrelated';") == "keep", "unrelated route preserved");
                Assert(db.Scalar("SELECT IsActive FROM RoutingItem WHERE Id='unrelated';") == "0", "other route deactivated");
            }
            var disposed = new NativeDatabase(dir); disposed.Dispose(); disposed.Dispose();
            Reject(delegate { disposed.Exec("SELECT 1;"); }, "disposed database cannot call unloaded native functions");
            string backup = Directory.GetDirectories(Path.Combine(dir, "backups")).Single();
            Assert(File.Exists(Path.Combine(backup, "guiNConfig.json")) && File.Exists(Path.Combine(backup, "guiNDB.db")), "reconfigure backs up JSON and database");
            Reject(delegate { ClientConfig.Write(dir, link, true, false, 0); }, "invalid inbound port rejected before writes");
            File.Delete(Path.Combine(dir, "e_sqlite3.dll"));
            Assert(!File.Exists(Path.Combine(dir, "e_sqlite3.dll")), "SQLite library unlocked after Dispose for transactional install");
            // Synthetic config for the package verifier; it contains no usable personal credential.
            Support.WriteJson(Path.Combine(root, "probe-synthetic.json"), ConnectionProbe.Config(link, 23456));
        }
        private static int Main(string[] args)
        {
            string root = Path.Combine(Path.GetTempPath(), "AntonVPN-ConfigTests-" + Guid.NewGuid().ToString("N"));
            try
            {
                string payload = args.Length == 1 ? Path.GetFullPath(args[0]) : Path.GetFullPath(Path.Combine(".qa", "payload"));
                Directory.CreateDirectory(root);
                ParseTests(); RoutingTests(); PathAndJsonTests(root); RuntimeTests(root); DatabaseTests(root, payload);
                Console.WriteLine("CONFIG_TESTS_OK " + assertions + " assertions");
                return 0;
            }
            catch (Exception error) { Console.Error.WriteLine("CONFIG_TESTS_FAILED " + error.GetType().Name + ": " + error.Message); return 1; }
            finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
        }
    }
}
