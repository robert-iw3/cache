using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace C2Console
{
    public static class ThreatIntelCompiler
    {
        private static readonly string[] NoisyIps = { "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9" };
        private static readonly string[] SafeDomains = {
            "google.com", "bing.com", "yahoo.com", "microsoft.com", "windows.com",
            "adobe.com", "github.com", "apple.com", "ubuntu.com", "mozilla.org",
            "cloudflare.com", "amazon.com", "aws.amazon.com", "office.com",
            "localhost", "localdomain", "example.com"
        };

        // Pre-compiled regex for maximum performance
        private static readonly Regex AlertRegex = new Regex(@"^alert.*?msg:\s*""([^""]+)""", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex IpHeaderRegex = new Regex(@"->\s+\[?([0-9\.,]+)\]?\s+", RegexOptions.Compiled);
        private static readonly Regex ContentRegex = new Regex(@"content:\s*""([^""]+)""", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex ValidIpRegex = new Regex(@"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", RegexOptions.Compiled);
        private static readonly Regex ValidDomainRegex = new Regex(@"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public static async Task<(string[] Keys, string[] Titles)> SyncAndCompileRules(string scriptDir)
        {
            List<string> tiKeys = new List<string>();
            List<string> tiTitles = new List<string>();
            
            string cacheMarker = Path.Combine(scriptDir, "threatintel.cache");
            string suricataDir = Path.Combine(scriptDir, "suricata", "upstream");
            bool needsDownload = true;

            if (File.Exists(cacheMarker) && (DateTime.Now - File.GetLastWriteTime(cacheMarker)).TotalHours < 24)
            {
                needsDownload = false;
                Program.WriteDiag("Using cached Threat Intel (rules < 24 hours old)", "STARTUP");
            }

            if (needsDownload || !Directory.Exists(suricataDir))
            {
                Directory.CreateDirectory(suricataDir);
                await DownloadRules(suricataDir);
                File.WriteAllText(cacheMarker, DateTime.Now.ToString("O")); // Touch cache file
            }

            int suricataCount = 0;
            foreach (var file in Directory.GetFiles(suricataDir, "*.rules"))
            {
                foreach (var line in File.ReadLines(file))
                {
                    var alertMatch = AlertRegex.Match(line);
                    if (!alertMatch.Success) continue;

                    string msg = "Suricata: " + alertMatch.Groups[1].Value;

                    // 1. IP Header Extraction
                    var ipMatch = IpHeaderRegex.Match(line);
                    if (ipMatch.Success)
                    {
                        var destIps = ipMatch.Groups[1].Value.Split(',');
                        foreach (var ip in destIps)
                        {
                            if (ValidIpRegex.IsMatch(ip) && Array.IndexOf(NoisyIps, ip) == -1)
                            {
                                tiKeys.Add(ip);
                                tiTitles.Add(msg);
                                suricataCount++;
                            }
                        }
                    }

                    // 2. Strict Content Parsing
                    var contentMatches = ContentRegex.Matches(line);
                    foreach (Match cMatch in contentMatches)
                    {
                        string val = cMatch.Groups[1].Value.ToLowerInvariant();
                        val = Regex.Replace(val, @"\|[0-9a-f]{2}\|", ".").Trim('.');

                        if (Array.IndexOf(NoisyIps, val) != -1 || IsSafeDomain(val)) continue;

                        bool isIp = ValidIpRegex.IsMatch(val);
                        bool isDomain = ValidDomainRegex.IsMatch(val);

                        if (isIp || isDomain)
                        {
                            string cleanVal = isDomain && !val.StartsWith(".") ? "." + val : val;
                            tiKeys.Add(cleanVal);
                            tiTitles.Add(msg);
                            suricataCount++;
                        }
                    }
                }
            }

            Program.WriteDiag($"Gatekeeper Compilation: Parsed {suricataCount} signatures from Suricata.", "STARTUP");
            Program.WriteDiag($"Threat Intel Compilation Complete. Passing {tiKeys.Count} signatures to Memory.", "STARTUP");
            
            return (tiKeys.ToArray(), tiTitles.ToArray());
        }

        private static bool IsSafeDomain(string val)
        {
            foreach (var safe in SafeDomains)
            {
                if (val == safe || val.EndsWith("." + safe)) return true;
            }
            return false;
        }

        private static async Task DownloadRules(string outputDir)
        {
            var urls = new Dictionary<string, string>
            {
                { "ET_C2", "https://rules.emergingthreats.net/open/suricata-8.0.4/rules/emerging-c2.rules" },
                { "ET_Malware", "https://rules.emergingthreats.net/open/suricata-8.0.4/rules/emerging-malware.rules" },
                { "ThreatView_CS", "https://rules.emergingthreats.net/open/suricata-8.0.4/rules/threatview_CS_c2.rules" },
                { "ET_BotCC", "https://rules.emergingthreats.net/open/suricata-8.0.4/rules/emerging-botcc.rules" },
                { "AbuseCH_ThreatFox", "https://threatfox.abuse.ch/downloads/threatfox_suricata.rules" }
            };

            using var client = new HttpClient();
            foreach (var kvp in urls)
            {
                try
                {
                    Program.WriteDiag($"Fetching Suricata ruleset: {kvp.Key}", "STARTUP");
                    string content = await client.GetStringAsync(kvp.Value);
                    File.WriteAllText(Path.Combine(outputDir, $"{kvp.Key}.rules"), content);
                }
                catch { Program.WriteDiag($"Failed to sync {kvp.Key}. Relying on local cache.", "WARN"); }
            }
        }
    }
}