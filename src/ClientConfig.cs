using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace AntonVpn
{
    internal static class ClientConfig
    {
        internal static List<object> Rules()
        {
            var policy = Support.Json.Deserialize<Dictionary<string, object>>(Support.ResourceText("routing.json"));
            if ((string)policy["default"] != "direct") throw new InvalidOperationException("Не задан прямой маршрут по умолчанию.");
            var rules = new List<object>();
            foreach (var service in (Dictionary<string, object>)policy["services"])
            {
                var entry = (Dictionary<string, object>)service.Value;
                if (entry.ContainsKey("process_name")) rules.Add(Support.Obj("Id", Support.RoutingId + "-" + rules.Count,
                    "Remarks", service.Key + ": приложение", "Enabled", true, "OutboundTag", "proxy", "Process", entry["process_name"]));
                var domains = new List<string>();
                string[] names = { "domain_suffix", "domain", "domain_regex" }, prefixes = { "domain:", "full:", "regexp:" };
                for (int i = 0; i < names.Length; i++) if (entry.ContainsKey(names[i]))
                    foreach (string domain in (IEnumerable)entry[names[i]]) domains.Add(prefixes[i] + domain);
                if (domains.Count > 0) rules.Add(Support.Obj("Id", Support.RoutingId + "-" + rules.Count,
                    "Remarks", service.Key, "Enabled", true, "OutboundTag", "proxy", "Domain", domains));
            }
            rules.Add(Support.Obj("Id", Support.RoutingId + "-direct", "Remarks", "Остальной интернет — напрямую",
                "Enabled", true, "OutboundTag", "direct", "Network", "tcp,udp"));
            return rules;
        }
        internal static void Write(string dir, VlessLink link, bool tun, bool autoRun, int port)
        {
            if (link == null) throw new ArgumentNullException("link");
            if (port < 1 || port > 65535) throw new ArgumentOutOfRangeException("port");
            string configDir = Path.Combine(dir, "guiConfigs");
            Directory.CreateDirectory(configDir);
            string jsonFile = Path.Combine(configDir, "guiNConfig.json");
            if (File.Exists(jsonFile))
            {
                string backup = Path.Combine(dir, "backups", DateTime.UtcNow.ToString("yyyyMMddTHHmmssfffZ"));
                Directory.CreateDirectory(backup);
                foreach (string name in new[] { "guiNConfig.json", "guiNDB.db" })
                    if (File.Exists(Path.Combine(configDir, name))) File.Copy(Path.Combine(configDir, name), Path.Combine(backup, name));
            }
            using (var db = new NativeDatabase(dir))
            {
                db.Exec(Support.ResourceText("schema.sql"));
                db.Exec("BEGIN IMMEDIATE;");
                try
                {
                    db.Upsert("ProfileItem", Support.Obj("IndexId", Support.ProfileId, "ConfigType", 5, "CoreType", 24,
                        "ConfigVersion", 4, "Subid", "", "IsSub", 0, "PreSocksPort", 0, "DisplayLog", 1,
                        "Remarks", "Мой VPN — личный профиль", "Address", link.Server, "Port", link.Port, "Password", link.Uuid,
                        "Username", "", "Network", "raw", "HeaderType", "", "RequestHost", "", "Path", "",
                        "StreamSecurity", "reality", "AllowInsecure", "false", "Sni", link.Sni, "Alpn", link.Alpn ?? "",
                        "Fingerprint", link.Fingerprint, "PublicKey", link.PublicKey, "ShortId", link.ShortId,
                        "SpiderX", link.SpiderX, "Mldsa65Verify", "", "Extra", "", "MuxEnabled", 0, "Cert", "",
                        "CertSha", "", "EchConfigList", "", "VerifyPeerCertByName", "", "Finalmask", "",
                        "ProtoExtra", Support.Json.Serialize(Support.Obj("Flow", link.Flow)), "TransportExtra", "{}",
                        "Ports", "", "AlterId", 0, "Flow", "", "Id", "", "Security", ""));
                    db.Exec("UPDATE RoutingItem SET IsActive=0 WHERE IsActive=1;");
                    var rules = Rules();
                    db.Upsert("RoutingItem", Support.Obj("Id", Support.RoutingId, "Remarks", "Выбранные сервисы через VPN; Google и остальное напрямую",
                        "Url", "", "RuleSet", Support.Json.Serialize(rules), "RuleNum", rules.Count, "Enabled", 1,
                        "Locked", 0, "CustomIcon", "", "CustomRulesetPath4Singbox", "", "DomainStrategy", "AsIs",
                        "DomainStrategy4Singbox", "", "Sort", -1, "IsActive", 1));
                    db.Upsert("ProfileExItem", Support.Obj("IndexId", Support.ProfileId, "Delay", 0, "Speed", 0, "Sort", 1, "Message", "", "IpInfo", ""));
                    db.Exec("COMMIT;");
                }
                catch { db.Exec("ROLLBACK;"); throw; }
            }
            var config = Support.Obj("IndexId", Support.ProfileId,
                "RoutingBasicItem", Support.Obj("DomainStrategy", "AsIs", "DomainStrategy4Singbox", "", "RoutingIndexId", Support.RoutingId),
                "CoreBasicItem", Support.Obj("LogEnabled", true, "Loglevel", "warning", "DefFingerprint", "chrome"),
                "UiItem", Support.Obj("CurrentLanguage", "ru", "Hide2TrayWhenClose", true, "AutoHideStartup", true),
                "GuiItem", Support.Obj("AutoRun", autoRun, "AutoUpdateInterval", 0, "EnableLog", false),
                "SystemProxyItem", Support.Obj("SysProxyType", 2, "NotProxyLocalAddress", true),
                "TunModeItem", Support.Obj("EnableTun", tun, "AutoRoute", true, "StrictRoute", true, "Stack", "mixed", "Mtu", 1500,
                    "EnableIPv6Address", false, "IcmpRouting", "direct", "EnableLegacyProtect", false,
                    "IPv4Address", "172.19.0.1/30", "IPv6Address", "fdfe:dcba:9876::1/126"),
                "SimpleDNSItem", Support.Obj("UseSystemHosts", false, "AddCommonHosts", false, "FakeIP", false, "GlobalFakeIp", false,
                    "BlockBindingQuery", true, "BlockAAAAQuery", true, "DirectDNS", "localhost", "RemoteDNS", "https://1.1.1.1/dns-query",
                    "BootstrapDNS", "1.1.1.1", "Strategy4Freedom", "UseIPv4", "Strategy4Proxy", "UseIPv4", "Strategy4ProxyDial", "UseIPv4"),
                "Inbound", new[] { Support.Obj("LocalPort", port, "Protocol", "socks", "UdpEnabled", true, "SniffingEnabled", true,
                    "DestOverride", new[] { "http", "tls" }, "RouteOnly", false, "AllowLANConn", false) },
                "CoreTypeItem", new[] { Support.Obj("ConfigType", 5, "CoreType", 24) });
            Support.WriteJson(jsonFile, config);
        }
    }
}
