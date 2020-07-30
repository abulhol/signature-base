rule TSCookie {
          meta:
            description = "detect TSCookie in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "https://blogs.jpcert.or.jp/en/2018/03/malware-tscooki-7aa0.html"
            hash1 = "6d2f5675630d0dae65a796ac624fb90f42f35fbe5dec2ec8f4adce5ebfaabf75"

          strings:
            $v1 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)" wide
            $b1 = { 68 D4 08 00 00 }

          condition: all of them
}

rule TSC_Loader {
          meta:
            description = "detect TSCookie Loader in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $v1 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)" wide
            $b1 = { 68 78 0B 00 00 }

          condition: all of them
}

rule CobaltStrike {
          meta:
            description = "detect CobaltStrike Beacon in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "https://blogs.jpcert.or.jp/en/2018/08/volatility-plugin-for-detecting-cobalt-strike-beacon.html"
            hash1 = "154db8746a9d0244146648006cc94f120390587e02677b97f044c25870d512c3"
            hash2 = "f9b93c92ed50743cd004532ab379e3135197b6fb5341322975f4d7a98a0fcde7"

          strings:
            $v1 = { 73 70 72 6E 67 00 }
            $v2 = { 69 69 69 69 69 69 69 69 }

          condition: all of them
}
