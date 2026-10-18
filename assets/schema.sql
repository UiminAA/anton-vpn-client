CREATE TABLE IF NOT EXISTS ProfileItem (
 IndexId varchar PRIMARY KEY NOT NULL, ConfigType integer, CoreType integer, ConfigVersion integer,
 Subid varchar, IsSub integer, PreSocksPort integer, DisplayLog integer, Remarks varchar, Address varchar,
 Port integer, Password varchar, Username varchar, Network varchar, HeaderType varchar, RequestHost varchar,
 Path varchar, StreamSecurity varchar, AllowInsecure varchar, Sni varchar, Alpn varchar, Fingerprint varchar,
 PublicKey varchar, ShortId varchar, SpiderX varchar, Mldsa65Verify varchar, Extra varchar, MuxEnabled integer,
 Cert varchar, CertSha varchar, EchConfigList varchar, VerifyPeerCertByName varchar, Finalmask varchar,
 ProtoExtra varchar, TransportExtra varchar, Ports varchar, AlterId integer, Flow varchar, Id varchar, Security varchar
);
CREATE TABLE IF NOT EXISTS ProfileExItem (
 IndexId varchar PRIMARY KEY NOT NULL, Delay integer, Speed float, Sort integer, Message varchar, IpInfo varchar
);
CREATE TABLE IF NOT EXISTS RoutingItem (
 Id varchar PRIMARY KEY NOT NULL, Remarks varchar, Url varchar, RuleSet varchar, RuleNum integer,
 Enabled integer, Locked integer, CustomIcon varchar, CustomRulesetPath4Singbox varchar,
 DomainStrategy varchar, DomainStrategy4Singbox varchar, Sort integer, IsActive integer
);
