# ===== Global DNS Propagation Check =====
# ------------------- DNS PROPAGATION PROBE -------------------
# This check answers the other question operators hit constantly: "I added the
# record -- has it actually propagated everywhere yet?"
#
# A single recursive resolver (the one this server uses) can only ever tell you
# what THAT resolver currently has cached. When a zone was just edited, when the
# authoritative nameservers are out of sync, or when a stale delegation is still
# being served, different public resolvers around the world return DIFFERENT
# answers for the same name. Azure Communication Services verifies domains
# through public DNS, so a record that is only visible from some vantage points
# will verify intermittently (or not at all).
#
# We therefore query a curated catalog of well-known public DNS resolvers spread
# across regions and compare their answers:
#   * every responder returns the same non-empty answer  -> fully propagated
#   * some responders have the record, others do not     -> still propagating
#   * responders return DIFFERENT non-empty answers      -> inconsistent answers
#
# DESIGN NOTES
#
# 1) NO bulk resolver dataset. The standalone propagation tool ships a 60k-row
#    public-dns.info CSV plus a processed cache. That is far too heavy for this
#    single-file app, so we embed a small, curated, geographically spread
#    catalog instead. Operators can override it entirely with
#    ACS_PROPAGATION_RESOLVERS (see Get-DnsPropagationResolverCatalog).
#
# 2) SINGLE-THREADED PARALLEL I/O. We deliberately do NOT use
#    [Parallel]::ForEach here. That helper invokes PowerShell functions on .NET
#    worker threads that share ONE runspace, which is not thread-safe. Instead
#    we open one UDP socket per resolver, send every query up front, and then
#    wait on all sockets at once with [Socket]::Select. That is genuinely
#    concurrent at the network level, completes in roughly one timeout window
#    regardless of resolver count, and touches no PowerShell state concurrently.
#
# 3) EDNS0. Each query advertises a 4096-byte UDP payload size (RFC 6891) so
#    large TXT/DKIM answers come back in one datagram. Truncated answers still
#    get a bounded, sequential TCP retry pass.
#
# SECURITY: the resolver list is operator-controlled (never derived from the
# queried domain), every entry is validated as a public IP literal via
# Test-IsPublicIpAddress (16b-WebsiteProbe.ps1) before a socket is opened, the
# fan-out size is capped, and both the socket timeout and the receive buffer are
# bounded so a hostile resolver cannot pin a worker or exhaust memory.

# Map a user-facing record type to its DNS QTYPE code. Returns 0 for anything we
# do not support, which the caller treats as a validation failure.
function Get-DnsPropagationTypeCode {
  param([string]$RecordType)

  switch (([string]$RecordType).Trim().ToUpperInvariant()) {
    'A'     { return 1 }
    'NS'    { return 2 }
    'CNAME' { return 5 }
    'SOA'   { return 6 }
    'MX'    { return 15 }
    'TXT'   { return 16 }
    'AAAA'  { return 28 }
    'CAA'   { return 257 }
    default { return 0 }
  }
}

# The curated public-resolver catalog.
#
# Each entry carries the geography we render on the mini map. `anycast` marks
# operators that announce the same address from many points of presence: those
# resolvers answer from the POP nearest to THIS server, so the coordinates are
# the operator's primary location rather than where the query was actually
# served. The UI renders them with a distinct marker and says so.
#
# Regions: global (large anycast networks), namer, samer, europe, asia, oceania.
#
# Operators can replace the whole catalog with ACS_PROPAGATION_RESOLVERS using a
# simple pipe-delimited, semicolon-separated format:
#   ip|provider|countryCode|city|lat|lon|region|anycast(0|1); ip|...
# Malformed entries are skipped; if nothing valid parses we fall back to the
# built-in catalog so the check never silently degrades to zero resolvers.
function Get-DnsPropagationResolverCatalog {
  $builtIn = @(
    # ---- Large anycast networks (global reach, answered from the nearest POP) ----
    [pscustomobject]@{ ip = '1.1.1.1';         provider = 'Cloudflare';            countryCode = 'US'; city = 'San Francisco'; latitude = 37.77;  longitude = -122.42; region = 'global'; anycast = $true }
    [pscustomobject]@{ ip = '8.8.8.8';         provider = 'Google Public DNS';     countryCode = 'US'; city = 'Mountain View'; latitude = 37.42;  longitude = -122.08; region = 'global'; anycast = $true }
    [pscustomobject]@{ ip = '9.9.9.9';         provider = 'Quad9';                 countryCode = 'CH'; city = 'Zurich';        latitude = 47.37;  longitude = 8.54;    region = 'global'; anycast = $true }
    [pscustomobject]@{ ip = '208.67.222.222';  provider = 'OpenDNS (Cisco)';       countryCode = 'US'; city = 'San Jose';      latitude = 37.33;  longitude = -121.89; region = 'global'; anycast = $true }
    [pscustomobject]@{ ip = '94.140.14.14';    provider = 'AdGuard DNS';           countryCode = 'CY'; city = 'Limassol';      latitude = 34.71;  longitude = 33.02;   region = 'global'; anycast = $true }
    [pscustomobject]@{ ip = '45.90.28.0';      provider = 'NextDNS';               countryCode = 'FR'; city = 'Paris';         latitude = 48.86;  longitude = 2.35;    region = 'global'; anycast = $true }
    [pscustomobject]@{ ip = '193.110.81.0';    provider = 'dns0.eu';               countryCode = 'DE'; city = 'Berlin';        latitude = 52.52;  longitude = 13.40;   region = 'global'; anycast = $true }
    [pscustomobject]@{ ip = '76.76.2.0';       provider = 'Control D';             countryCode = 'CA'; city = 'Toronto';       latitude = 43.65;  longitude = -79.38;  region = 'global'; anycast = $true }
    [pscustomobject]@{ ip = '185.228.168.9';   provider = 'CleanBrowsing';         countryCode = 'US'; city = 'Washington';    latitude = 38.90;  longitude = -77.04;  region = 'global'; anycast = $true }

    # ---- North America ----
    [pscustomobject]@{ ip = '4.2.2.1';         provider = 'Lumen (Level 3)';       countryCode = 'US'; city = 'Broomfield';    latitude = 39.92;  longitude = -105.09; region = 'namer';  anycast = $true }
    [pscustomobject]@{ ip = '74.82.42.42';     provider = 'Hurricane Electric';    countryCode = 'US'; city = 'Fremont';       latitude = 37.55;  longitude = -121.99; region = 'namer';  anycast = $false }
    [pscustomobject]@{ ip = '149.112.121.10';  provider = 'CIRA Canadian Shield';  countryCode = 'CA'; city = 'Toronto';       latitude = 43.65;  longitude = -79.38;  region = 'namer';  anycast = $true }
    [pscustomobject]@{ ip = '156.154.70.1';    provider = 'Vercara UltraDNS';      countryCode = 'US'; city = 'Sterling';      latitude = 39.01;  longitude = -77.42;  region = 'namer';  anycast = $true }

    # ---- South America ----
    [pscustomobject]@{ ip = '200.221.11.100';  provider = 'UOL DNS';               countryCode = 'BR'; city = 'Sao Paulo';     latitude = -23.55; longitude = -46.63;  region = 'samer';  anycast = $false }

    # ---- Europe ----
    [pscustomobject]@{ ip = '84.200.69.80';    provider = 'DNS.WATCH';             countryCode = 'DE'; city = 'Frankfurt';     latitude = 50.11;  longitude = 8.68;    region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '91.239.100.100';  provider = 'UncensoredDNS';         countryCode = 'DK'; city = 'Copenhagen';    latitude = 55.68;  longitude = 12.57;   region = 'europe'; anycast = $true }
    [pscustomobject]@{ ip = '89.233.43.71';    provider = 'UncensoredDNS (unicast)'; countryCode = 'DK'; city = 'Copenhagen';  latitude = 55.68;  longitude = 12.57;   region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '80.67.169.12';    provider = 'FDN';                   countryCode = 'FR'; city = 'Paris';         latitude = 48.86;  longitude = 2.35;    region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '46.182.19.48';    provider = 'Digitale Gesellschaft'; countryCode = 'CH'; city = 'Zurich';        latitude = 47.37;  longitude = 8.54;    region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '77.88.8.8';       provider = 'Yandex DNS';            countryCode = 'RU'; city = 'Moscow';        latitude = 55.76;  longitude = 37.62;   region = 'europe'; anycast = $true }
    [pscustomobject]@{ ip = '194.150.168.168'; provider = 'AS250.net';             countryCode = 'DE'; city = 'Berlin';        latitude = 52.52;  longitude = 13.40;   region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '80.80.80.80';     provider = 'Freenom World';         countryCode = 'NL'; city = 'Amsterdam';     latitude = 52.37;  longitude = 4.90;    region = 'europe'; anycast = $true }

    # ---- Asia ----
    [pscustomobject]@{ ip = '223.5.5.5';       provider = 'AliDNS';                countryCode = 'CN'; city = 'Hangzhou';      latitude = 30.27;  longitude = 120.16;  region = 'asia';   anycast = $true }
    [pscustomobject]@{ ip = '119.29.29.29';    provider = 'DNSPod (Tencent)';      countryCode = 'CN'; city = 'Shenzhen';      latitude = 22.54;  longitude = 114.06;  region = 'asia';   anycast = $true }
    [pscustomobject]@{ ip = '114.114.114.114'; provider = '114DNS';                countryCode = 'CN'; city = 'Nanjing';       latitude = 32.06;  longitude = 118.80;  region = 'asia';   anycast = $true }
    [pscustomobject]@{ ip = '180.76.76.76';    provider = 'Baidu DNS';             countryCode = 'CN'; city = 'Beijing';       latitude = 39.90;  longitude = 116.41;  region = 'asia';   anycast = $true }
    [pscustomobject]@{ ip = '168.126.63.1';    provider = 'KT (Korea Telecom)';    countryCode = 'KR'; city = 'Seoul';         latitude = 37.57;  longitude = 126.98;  region = 'asia';   anycast = $false }
    [pscustomobject]@{ ip = '203.248.252.2';   provider = 'LG U+';                 countryCode = 'KR'; city = 'Seoul';         latitude = 37.57;  longitude = 126.98;  region = 'asia';   anycast = $false }
    [pscustomobject]@{ ip = '129.250.35.250';  provider = 'NTT';                   countryCode = 'JP'; city = 'Tokyo';         latitude = 35.68;  longitude = 139.69;  region = 'asia';   anycast = $true }

    # ---- Oceania ----
    [pscustomobject]@{ ip = '139.130.4.5';     provider = 'Telstra';               countryCode = 'AU'; city = 'Sydney';        latitude = -33.87; longitude = 151.21;  region = 'oceania'; anycast = $false }

    # ---- Community open resolvers (generated) ----
    # Sourced from the public-dns.info dataset, cross-referenced against the
    # standalone DNS Propagation Checker's vetted-healthy cache, then live-probed
    # before being committed here. Coordinates are the operator country reference
    # point, not a per-IP geolocation, so the map shows "a resolver in this
    # country" rather than claiming street-level accuracy. These exist so a
    # 100-resolver request has enough real vantage points to draw from; dead
    # entries are filtered out at request time by the health pre-check.
    [pscustomobject]@{ ip = '194.158.78.137'; provider = 'Andorra Telecom S.a.u.'; countryCode = 'AD'; city = 'Andorra la Vella'; latitude = 42.5; longitude = 1.5; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '138.219.249.221'; provider = 'Coop de Prov.Serv.Telef.Obras'; countryCode = 'AR'; city = 'Rafael Castillo'; latitude = -34.6; longitude = -58.4; region = 'samer'; anycast = $false }
    [pscustomobject]@{ ip = '200.89.142.74'; provider = 'Telecom Argentina S.A.'; countryCode = 'AR'; city = 'Buenos Aires'; latitude = -34.6; longitude = -58.4; region = 'samer'; anycast = $false }
    [pscustomobject]@{ ip = '80.123.196.122'; provider = 'A1 Telekom Austria AG'; countryCode = 'AT'; city = 'Dornbirn'; latitude = 48.2; longitude = 16.4; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '110.145.154.62'; provider = 'Telstra Corporation Ltd'; countryCode = 'AU'; city = 'Melbourne'; latitude = -33.9; longitude = 151.2; region = 'oceania'; anycast = $false }
    [pscustomobject]@{ ip = '111.118.223.243'; provider = 'Entity Data Pty Limited'; countryCode = 'AU'; city = ''; latitude = -33.9; longitude = 151.2; region = 'oceania'; anycast = $false }
    [pscustomobject]@{ ip = '139.134.5.51'; provider = 'Telstra Corporation Ltd'; countryCode = 'AU'; city = ''; latitude = -33.9; longitude = 151.2; region = 'oceania'; anycast = $false }
    [pscustomobject]@{ ip = '203.50.2.71'; provider = 'Telstra Corporation Ltd'; countryCode = 'AU'; city = 'Sydney'; latitude = -33.9; longitude = 151.2; region = 'oceania'; anycast = $false }
    [pscustomobject]@{ ip = '210.18.214.38'; provider = 'Brennan IT'; countryCode = 'AU'; city = 'Sunshine Coast'; latitude = -33.9; longitude = 151.2; region = 'oceania'; anycast = $false }
    [pscustomobject]@{ ip = '85.132.85.85'; provider = 'Delta Telecom Ltd'; countryCode = 'AZ'; city = ''; latitude = 40.4; longitude = 49.9; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '103.140.24.14'; provider = 'Hello IT'; countryCode = 'BD'; city = 'Cox''s Bazar'; latitude = 23.8; longitude = 90.4; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '103.143.237.206'; provider = 'ARK Network'; countryCode = 'BD'; city = ''; latitude = 23.8; longitude = 90.4; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '103.143.237.85'; provider = 'ARK Network'; countryCode = 'BD'; city = ''; latitude = 23.8; longitude = 90.4; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '103.145.164.162'; provider = 'Speed 69.Net'; countryCode = 'BD'; city = 'Tejgaon'; latitude = 23.8; longitude = 90.4; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '103.145.164.231'; provider = 'Speed 69.Net'; countryCode = 'BD'; city = 'Dhaka'; latitude = 23.8; longitude = 90.4; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '103.153.48.174'; provider = 'MAYA SOFT'; countryCode = 'BD'; city = 'Mymensingh'; latitude = 23.8; longitude = 90.4; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '194.6.227.15'; provider = 'VERIXI SA'; countryCode = 'BE'; city = ''; latitude = 50.8; longitude = 4.4; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '185.165.96.225'; provider = 'Global Electronic Solutions LT'; countryCode = 'BG'; city = ''; latitude = 42.7; longitude = 23.3; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '202.152.80.38'; provider = 'UNN'; countryCode = 'BN'; city = 'Bandar Seri Begawan'; latitude = 4.9; longitude = 114.9; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '168.181.247.29'; provider = 'gotcha net internet provider'; countryCode = 'BR'; city = 'São Paulo'; latitude = -23.5; longitude = -46.6; region = 'samer'; anycast = $false }
    [pscustomobject]@{ ip = '168.181.247.54'; provider = 'gotcha net internet provider'; countryCode = 'BR'; city = 'São Paulo'; latitude = -23.5; longitude = -46.6; region = 'samer'; anycast = $false }
    [pscustomobject]@{ ip = '177.131.18.34'; provider = 'Compuservice Empreendimentos L'; countryCode = 'BR'; city = 'Macapá'; latitude = -23.5; longitude = -46.6; region = 'samer'; anycast = $false }
    [pscustomobject]@{ ip = '179.228.250.125'; provider = 'TELEFONICA BRASIL S.A'; countryCode = 'BR'; city = 'São Paulo'; latitude = -23.5; longitude = -46.6; region = 'samer'; anycast = $false }
    [pscustomobject]@{ ip = '190.89.22.77'; provider = 'RDS TECNOLOGIA-ME'; countryCode = 'BR'; city = 'São Luís'; latitude = -23.5; longitude = -46.6; region = 'samer'; anycast = $false }
    [pscustomobject]@{ ip = '200.195.170.186'; provider = 'Ligga Telecomunicacoes S.A.'; countryCode = 'BR'; city = 'Ivai'; latitude = -23.5; longitude = -46.6; region = 'samer'; anycast = $false }
    [pscustomobject]@{ ip = '178.124.148.226'; provider = 'Republican Unitary Telecommuni'; countryCode = 'BY'; city = 'Minsk'; latitude = 53.9; longitude = 27.6; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '149.112.122.20'; provider = 'CIRADNS3'; countryCode = 'CA'; city = ''; latitude = 43.7; longitude = -79.4; region = 'namer'; anycast = $false }
    [pscustomobject]@{ ip = '208.91.112.52'; provider = 'FORTINET'; countryCode = 'CA'; city = 'Burnaby'; latitude = 43.7; longitude = -79.4; region = 'namer'; anycast = $false }
    [pscustomobject]@{ ip = '141.195.95.131'; provider = 'Init7 (Switzerland) Ltd.'; countryCode = 'CH'; city = 'Affoltern am Albis'; latitude = 47.4; longitude = 8.5; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '195.186.1.111'; provider = 'Bluewin'; countryCode = 'CH'; city = ''; latitude = 47.4; longitude = 8.5; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '195.186.4.192'; provider = 'Bluewin'; countryCode = 'CH'; city = ''; latitude = 47.4; longitude = 8.5; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '195.245.237.35'; provider = 'fenaco Genossenschaft'; countryCode = 'CH'; city = ''; latitude = 47.4; longitude = 8.5; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '81.17.17.170'; provider = 'Private Layer INC'; countryCode = 'CH'; city = 'Zurich'; latitude = 47.4; longitude = 8.5; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '85.90.9.166'; provider = 'netplusFR SA'; countryCode = 'CH'; city = 'Fribourg'; latitude = 47.4; longitude = 8.5; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '190.151.104.178'; provider = 'ENTEL CHILE S.A.'; countryCode = 'CL'; city = 'Vallenar'; latitude = -33.4; longitude = -70.7; region = 'samer'; anycast = $false }
    [pscustomobject]@{ ip = '200.68.46.21'; provider = 'CTC. CORP S.A. TELEFONICA EMPR'; countryCode = 'CL'; city = 'Chimbarongo'; latitude = -33.4; longitude = -70.7; region = 'samer'; anycast = $false }
    [pscustomobject]@{ ip = '201.148.107.14'; provider = 'HOSTING.'; countryCode = 'CL'; city = 'Santiago'; latitude = -33.4; longitude = -70.7; region = 'samer'; anycast = $false }
    [pscustomobject]@{ ip = '114.114.115.115'; provider = 'COGENT-174'; countryCode = 'CN'; city = ''; latitude = 39.9; longitude = 116.4; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '181.129.36.242'; provider = 'EPM Telecomunicaciones S.A. E.'; countryCode = 'CO'; city = 'Bogotá'; latitude = 4.7; longitude = -74.1; region = 'samer'; anycast = $false }
    [pscustomobject]@{ ip = '181.143.37.202'; provider = 'EPM Telecomunicaciones S.A. E.'; countryCode = 'CO'; city = 'Medellín'; latitude = 4.7; longitude = -74.1; region = 'samer'; anycast = $false }
    [pscustomobject]@{ ip = '181.48.196.182'; provider = 'Telmex Colombia S.A.'; countryCode = 'CO'; city = 'Bogotá'; latitude = 4.7; longitude = -74.1; region = 'samer'; anycast = $false }
    [pscustomobject]@{ ip = '181.49.102.21'; provider = 'Telmex Colombia S.A.'; countryCode = 'CO'; city = 'Pereira'; latitude = 4.7; longitude = -74.1; region = 'samer'; anycast = $false }
    [pscustomobject]@{ ip = '181.49.210.138'; provider = 'Telmex Colombia S.A.'; countryCode = 'CO'; city = 'Medellín'; latitude = 4.7; longitude = -74.1; region = 'samer'; anycast = $false }
    [pscustomobject]@{ ip = '190.145.215.198'; provider = 'Telmex Colombia S.A.'; countryCode = 'CO'; city = 'Bogotá'; latitude = 4.7; longitude = -74.1; region = 'samer'; anycast = $false }
    [pscustomobject]@{ ip = '190.171.97.250'; provider = 'Telecable Economico S.A.'; countryCode = 'CR'; city = 'San José'; latitude = 9.9; longitude = -84.1; region = 'namer'; anycast = $false }
    [pscustomobject]@{ ip = '185.43.135.1'; provider = 'CZ.NIC z.s.p.o.'; countryCode = 'CZ'; city = ''; latitude = 50.1; longitude = 14.4; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '89.190.65.200'; provider = 'N_SYS s.r.o.'; countryCode = 'CZ'; city = 'Broumov'; latitude = 50.1; longitude = 14.4; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '94.127.135.212'; provider = 'TFnet s.r.o.'; countryCode = 'CZ'; city = 'Tanvald'; latitude = 50.1; longitude = 14.4; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '185.93.180.131'; provider = 'M247 Ltd'; countryCode = 'DE'; city = 'Frankfurt am Main'; latitude = 50.1; longitude = 8.7; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '194.25.0.60'; provider = 'Deutsche Telekom AG'; countryCode = 'DE'; city = 'Rehau'; latitude = 50.1; longitude = 8.7; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '217.160.70.42'; provider = 'IONOS SE'; countryCode = 'DE'; city = ''; latitude = 50.1; longitude = 8.7; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '78.31.67.99'; provider = 'myLoc managed IT AG'; countryCode = 'DE'; city = ''; latitude = 50.1; longitude = 8.7; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '81.16.18.228'; provider = 'netcup GmbH'; countryCode = 'DE'; city = ''; latitude = 50.1; longitude = 8.7; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '81.16.19.65'; provider = 'netcup GmbH'; countryCode = 'DE'; city = ''; latitude = 50.1; longitude = 8.7; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '81.27.217.7'; provider = 'GlobalConnect A S'; countryCode = 'DK'; city = 'Odense'; latitude = 55.7; longitude = 12.6; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '157.100.63.48'; provider = 'NEDETEL S.A.'; countryCode = 'EC'; city = ''; latitude = -0.2; longitude = -78.5; region = 'samer'; anycast = $false }
    [pscustomobject]@{ ip = '170.239.204.230'; provider = 'FIBERNET'; countryCode = 'EC'; city = 'Ambato'; latitude = -0.2; longitude = -78.5; region = 'samer'; anycast = $false }
    [pscustomobject]@{ ip = '94.198.55.64'; provider = 'LLC Smart Ape'; countryCode = 'EE'; city = ''; latitude = 59.4; longitude = 24.8; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '41.33.166.19'; provider = 'TE-AS'; countryCode = 'EG'; city = 'Cairo'; latitude = 30; longitude = 31.2; region = 'africa'; anycast = $false }
    [pscustomobject]@{ ip = '5.1.38.155'; provider = 'Prisco Electronica S.L.'; countryCode = 'ES'; city = 'Roses'; latitude = 40.4; longitude = -3.7; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '77.26.214.15'; provider = 'R Cable y Telecable Telecomuni'; countryCode = 'ES'; city = 'Sanxenxo'; latitude = 40.4; longitude = -3.7; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '81.9.198.12'; provider = 'Euskaltel S.A.'; countryCode = 'ES'; city = 'Madrid'; latitude = 40.4; longitude = -3.7; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '81.9.198.202'; provider = 'Euskaltel S.A.'; countryCode = 'ES'; city = 'Madrid'; latitude = 40.4; longitude = -3.7; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '81.9.198.217'; provider = 'Euskaltel S.A.'; countryCode = 'ES'; city = 'Madrid'; latitude = 40.4; longitude = -3.7; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '82.223.43.222'; provider = 'IONOS SE'; countryCode = 'ES'; city = 'Madrid'; latitude = 40.4; longitude = -3.7; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '85.23.204.137'; provider = 'DNA Oyj'; countryCode = 'FI'; city = 'Oulu'; latitude = 60.2; longitude = 24.9; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '109.5.33.66'; provider = 'Societe Francaise Du Radiotele'; countryCode = 'FR'; city = 'Paris'; latitude = 48.9; longitude = 2.4; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '141.95.6.51'; provider = 'OVH SAS'; countryCode = 'FR'; city = ''; latitude = 48.9; longitude = 2.4; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '15.188.45.248'; provider = 'AMAZON-02'; countryCode = 'FR'; city = 'Paris'; latitude = 48.9; longitude = 2.4; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '151.80.145.143'; provider = 'OVH SAS'; countryCode = 'FR'; city = 'Roubaix'; latitude = 48.9; longitude = 2.4; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '5.135.166.77'; provider = 'OVH SAS'; countryCode = 'FR'; city = 'Bonneuil-sur-Marne'; latitude = 48.9; longitude = 2.4; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '5.39.71.50'; provider = 'OVH SAS'; countryCode = 'FR'; city = ''; latitude = 48.9; longitude = 2.4; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '109.228.0.238'; provider = 'IONOS SE'; countryCode = 'GB'; city = ''; latitude = 51.5; longitude = -0.1; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '167.98.161.41'; provider = 'Exponential-E Ltd.'; countryCode = 'GB'; city = 'London'; latitude = 51.5; longitude = -0.1; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '167.98.171.242'; provider = 'Exponential-E Ltd.'; countryCode = 'GB'; city = 'Sheffield'; latitude = 51.5; longitude = -0.1; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '194.168.4.123'; provider = 'Virgin Media Limited'; countryCode = 'GB'; city = 'Liverpool'; latitude = 51.5; longitude = -0.1; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '195.99.66.220'; provider = 'British Telecommunications PLC'; countryCode = 'GB'; city = ''; latitude = 51.5; longitude = -0.1; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '5.11.11.11'; provider = 'Liquid Telecommunications Ltd'; countryCode = 'GB'; city = ''; latitude = 51.5; longitude = -0.1; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '212.72.130.21'; provider = 'Caucasus Online Ltd.'; countryCode = 'GE'; city = ''; latitude = 41.7; longitude = 44.8; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '192.71.166.92'; provider = 'SYNAPSECOM S.A. Provider of Te'; countryCode = 'GR'; city = 'Thessaloniki'; latitude = 38; longitude = 23.7; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '194.177.199.1'; provider = 'University Of Ioannina'; countryCode = 'GR'; city = ''; latitude = 38; longitude = 23.7; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '195.167.123.245'; provider = 'OTEnet S .A .'; countryCode = 'GR'; city = 'Thessaloniki'; latitude = 38; longitude = 23.7; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '195.251.19.1'; provider = 'National Infrastructures for R'; countryCode = 'GR'; city = 'Marousi'; latitude = 38; longitude = 23.7; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '212.251.32.202'; provider = 'Forthnet'; countryCode = 'GR'; city = 'Athens'; latitude = 38; longitude = 23.7; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '113.28.67.147'; provider = 'HKT Limited'; countryCode = 'HK'; city = 'Central'; latitude = 22.3; longitude = 114.2; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '175.45.16.253'; provider = 'HKBN Enterprise Solutions HK L'; countryCode = 'HK'; city = 'Central'; latitude = 22.3; longitude = 114.2; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '202.131.73.38'; provider = 'HKBN Enterprise Solutions HK L'; countryCode = 'HK'; city = 'Tai Kok Tsui'; latitude = 22.3; longitude = 114.2; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '202.181.242.131'; provider = 'HongKong Commercial Internet E'; countryCode = 'HK'; city = ''; latitude = 22.3; longitude = 114.2; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '203.198.167.39'; provider = 'HKT Limited'; countryCode = 'HK'; city = 'Central'; latitude = 22.3; longitude = 114.2; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '223.255.176.195'; provider = 'HKBN Enterprise Solutions HK L'; countryCode = 'HK'; city = 'Wanchai'; latitude = 22.3; longitude = 114.2; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '83.131.4.217'; provider = 'Hrvatski Telekom d.d.'; countryCode = 'HR'; city = 'Velika Jamnicka'; latitude = 45.8; longitude = 16; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '109.61.113.35'; provider = 'Dravanet Co Ltd.'; countryCode = 'HU'; city = 'Pécs'; latitude = 47.5; longitude = 19; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '195.228.230.148'; provider = 'Magyar Telekom plc.'; countryCode = 'HU'; city = 'Budapest'; latitude = 47.5; longitude = 19; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '80.249.168.172'; provider = 'Magyar Telekom plc.'; countryCode = 'HU'; city = 'Budapest'; latitude = 47.5; longitude = 19; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '81.183.227.40'; provider = 'Magyar Telekom plc.'; countryCode = 'HU'; city = 'Budapest'; latitude = 47.5; longitude = 19; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '103.175.237.3'; provider = 'PT Marva Global Telekomunikasi'; countryCode = 'ID'; city = 'Malang'; latitude = -6.2; longitude = 106.8; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '202.92.207.33'; provider = 'PT Hyperindo Media Perkasa'; countryCode = 'ID'; city = 'Jakarta'; latitude = -6.2; longitude = 106.8; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '36.67.236.161'; provider = 'PT Telekomunikasi Indonesia'; countryCode = 'ID'; city = 'Mangunsari'; latitude = -6.2; longitude = 106.8; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '54.229.171.243'; provider = 'AMAZON-02'; countryCode = 'IE'; city = 'Dublin'; latitude = 53.3; longitude = -6.3; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '185.106.131.141'; provider = 'O.m.c. Computers & Communicati'; countryCode = 'IL'; city = ''; latitude = 32.1; longitude = 34.8; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '91.223.106.229'; provider = 'O.m.c. Computers & Communicati'; countryCode = 'IL'; city = 'Tel Aviv'; latitude = 32.1; longitude = 34.8; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '103.13.112.251'; provider = 'LeapSwitch Networks Pvt Ltd'; countryCode = 'IN'; city = ''; latitude = 19.1; longitude = 72.9; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '103.174.102.61'; provider = 'IDIGITALCAMP WEB SERVICES'; countryCode = 'IN'; city = ''; latitude = 19.1; longitude = 72.9; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '103.241.181.28'; provider = 'CtrlS'; countryCode = 'IN'; city = ''; latitude = 19.1; longitude = 72.9; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '169.38.73.5'; provider = 'SOFTLAYER'; countryCode = 'IN'; city = 'Chennai'; latitude = 19.1; longitude = 72.9; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '213.176.123.5'; provider = 'Iranian Research Organization'; countryCode = 'IR'; city = ''; latitude = 35.7; longitude = 51.4; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '81.91.144.116'; provider = 'Farabord Dadeh Haye Iranian Co'; countryCode = 'IR'; city = 'Tehran'; latitude = 35.7; longitude = 51.4; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '154.14.16.251'; provider = 'GTT Communications Inc.'; countryCode = 'IT'; city = 'Canossa'; latitude = 41.9; longitude = 12.5; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '194.53.180.252'; provider = 'Computer System'; countryCode = 'IT'; city = 'Terranova da Sibari'; latitude = 41.9; longitude = 12.5; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '2.40.63.222'; provider = 'Vodafone Italia S.p.A.'; countryCode = 'IT'; city = 'Castel Maggiore'; latitude = 41.9; longitude = 12.5; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '84.253.140.132'; provider = 'Irideos S.p.A.'; countryCode = 'IT'; city = 'Rome'; latitude = 41.9; longitude = 12.5; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '124.32.115.205'; provider = 'ARTERIA Networks Corporation'; countryCode = 'JP'; city = 'Kawaguchi'; latitude = 35.7; longitude = 139.7; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '153.120.88.148'; provider = 'SAKURA Internet Inc.'; countryCode = 'JP'; city = ''; latitude = 35.7; longitude = 139.7; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '202.210.190.99'; provider = 'BEKKOAME INTERNET INC.'; countryCode = 'JP'; city = ''; latitude = 35.7; longitude = 139.7; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '210.171.38.41'; provider = 'Yahoo Japan Corporation'; countryCode = 'JP'; city = ''; latitude = 35.7; longitude = 139.7; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '59.158.8.83'; provider = 'ARTERIA Networks Corporation'; countryCode = 'JP'; city = 'Sapporo'; latitude = 35.7; longitude = 139.7; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '66.42.33.24'; provider = 'AS-CHOOPA'; countryCode = 'JP'; city = 'Heiwajima'; latitude = 35.7; longitude = 139.7; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '134.75.122.2'; provider = 'Hoseo University'; countryCode = 'KR'; city = ''; latitude = 37.6; longitude = 127; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '168.154.160.4'; provider = 'SK Co.'; countryCode = 'KR'; city = 'Seongnam-si'; latitude = 37.6; longitude = 127; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '168.154.224.50'; provider = 'SK Co.'; countryCode = 'KR'; city = ''; latitude = 37.6; longitude = 127; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '202.30.143.11'; provider = 'Shinbiro'; countryCode = 'KR'; city = ''; latitude = 37.6; longitude = 127; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '203.225.255.11'; provider = 'Korea Telecom'; countryCode = 'KR'; city = ''; latitude = 37.6; longitude = 127; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '211.115.194.3'; provider = 'Sejong Telecom'; countryCode = 'KR'; city = ''; latitude = 37.6; longitude = 127; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '195.88.223.73'; provider = 'Kuwait Petroleum Corporation'; countryCode = 'KW'; city = 'Kuwait City'; latitude = 29.4; longitude = 48; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '5.63.111.235'; provider = 'JSC Kazakhtelecom'; countryCode = 'KZ'; city = 'Aktobe'; latitude = 43.2; longitude = 76.9; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '79.137.181.102'; provider = 'Ecotel Ltd.'; countryCode = 'KZ'; city = 'Taraz'; latitude = 43.2; longitude = 76.9; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '46.148.26.40'; provider = 'Infium UAB'; countryCode = 'LT'; city = ''; latitude = 54.7; longitude = 25.3; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '82.135.203.178'; provider = 'Telia Lietuva AB'; countryCode = 'LT'; city = 'Vilnius'; latitude = 54.7; longitude = 25.3; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '88.119.203.210'; provider = 'Telia Lietuva AB'; countryCode = 'LT'; city = 'Kaunas'; latitude = 54.7; longitude = 25.3; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '92.61.44.7'; provider = 'Telia Lietuva AB'; countryCode = 'LT'; city = ''; latitude = 54.7; longitude = 25.3; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '77.93.22.17'; provider = 'Jsc Balticom'; countryCode = 'LV'; city = 'Riga'; latitude = 56.9; longitude = 24.1; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '83.99.220.7'; provider = 'Jsc Balticom'; countryCode = 'LV'; city = 'Riga'; latitude = 56.9; longitude = 24.1; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '91.200.67.156'; provider = 'SIA Tet'; countryCode = 'LV'; city = ''; latitude = 56.9; longitude = 24.1; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '165.16.58.124'; provider = 'Aljeel-net'; countryCode = 'LY'; city = ''; latitude = 32.9; longitude = 13.2; region = 'africa'; anycast = $false }
    [pscustomobject]@{ ip = '41.77.116.62'; provider = 'GTCOMM'; countryCode = 'MA'; city = 'Marrakesh'; latitude = 33.6; longitude = -7.6; region = 'africa'; anycast = $false }
    [pscustomobject]@{ ip = '95.65.9.171'; provider = 'StarNet Solutii SRL'; countryCode = 'MD'; city = 'Bălţi'; latitude = 47; longitude = 28.9; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '103.121.228.5'; provider = 'MyanmarAPN'; countryCode = 'MM'; city = 'Yangon'; latitude = 16.8; longitude = 96.2; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '202.131.254.166'; provider = 'Mobinet LLC. AS Mobinet Intern'; countryCode = 'MN'; city = ''; latitude = 47.9; longitude = 106.9; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '202.21.116.206'; provider = 'Mobinet LLC. AS Mobinet Intern'; countryCode = 'MN'; city = ''; latitude = 47.9; longitude = 106.9; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '202.5.200.8'; provider = 'Mongolian National Research an'; countryCode = 'MN'; city = ''; latitude = 47.9; longitude = 106.9; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '94.124.152.158'; provider = 'Idom Technologies SAS'; countryCode = 'MQ'; city = 'Riviere Salee'; latitude = 14.6; longitude = -61.1; region = 'namer'; anycast = $false }
    [pscustomobject]@{ ip = '41.216.125.179'; provider = 'Liquid Telecommunications Ltd'; countryCode = 'MU'; city = ''; latitude = -20.2; longitude = 57.5; region = 'africa'; anycast = $false }
    [pscustomobject]@{ ip = '186.96.11.240'; provider = 'TOTAL PLAY TELECOMUNICACIONES'; countryCode = 'MX'; city = 'Monterrey'; latitude = 19.4; longitude = -99.1; region = 'namer'; anycast = $false }
    [pscustomobject]@{ ip = '187.216.86.65'; provider = 'Uninet S.A. de C.V.'; countryCode = 'MX'; city = 'Hermosillo'; latitude = 19.4; longitude = -99.1; region = 'namer'; anycast = $false }
    [pscustomobject]@{ ip = '189.196.91.198'; provider = 'Mega Cable S.A. de C.V.'; countryCode = 'MX'; city = 'Monterrey'; latitude = 19.4; longitude = -99.1; region = 'namer'; anycast = $false }
    [pscustomobject]@{ ip = '189.204.6.253'; provider = 'Mexico Red de Telecomunicacion'; countryCode = 'MX'; city = 'Cuautitlan'; latitude = 19.4; longitude = -99.1; region = 'namer'; anycast = $false }
    [pscustomobject]@{ ip = '200.76.5.147'; provider = 'Alestra S. de R.L. de C.V.'; countryCode = 'MX'; city = 'San Luis Potosí City'; latitude = 19.4; longitude = -99.1; region = 'namer'; anycast = $false }
    [pscustomobject]@{ ip = '201.143.181.110'; provider = 'Telefonos del Noroeste S.A. de'; countryCode = 'MX'; city = 'San Luis Río Colorado'; latitude = 19.4; longitude = -99.1; region = 'namer'; anycast = $false }
    [pscustomobject]@{ ip = '1.9.165.210'; provider = 'TM Net Internet Service Provid'; countryCode = 'MY'; city = 'Petaling Jaya'; latitude = 3.1; longitude = 101.7; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '1.9.63.97'; provider = 'TM Net Internet Service Provid'; countryCode = 'MY'; city = 'Shah Alam'; latitude = 3.1; longitude = 101.7; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '103.13.123.16'; provider = 'Exa Bytes Network Sdn.Bhd.'; countryCode = 'MY'; city = ''; latitude = 3.1; longitude = 101.7; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '175.139.1.45'; provider = 'TM Net Internet Service Provid'; countryCode = 'MY'; city = 'Taiping'; latitude = 3.1; longitude = 101.7; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '202.184.80.21'; provider = 'TIME dotCom Berhad No. 14 Jala'; countryCode = 'MY'; city = 'Rawang'; latitude = 3.1; longitude = 101.7; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '210.187.25.147'; provider = 'TM Net Internet Service Provid'; countryCode = 'MY'; city = 'Puchong Batu Dua Belas'; latitude = 3.1; longitude = 101.7; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '41.218.90.154'; provider = 'Paratus-Telecom'; countryCode = 'NA'; city = 'Windhoek'; latitude = -22.6; longitude = 17.1; region = 'africa'; anycast = $false }
    [pscustomobject]@{ ip = '178.62.197.147'; provider = 'DIGITALOCEAN-ASN'; countryCode = 'NL'; city = 'Amsterdam'; latitude = 52.4; longitude = 4.9; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '45.14.48.185'; provider = 'Itglobal.com Nl B.v.'; countryCode = 'NL'; city = ''; latitude = 52.4; longitude = 4.9; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '85.146.233.162'; provider = 'Vodafone Libertel B.V.'; countryCode = 'NL'; city = 'Maastricht'; latitude = 52.4; longitude = 4.9; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '88.221.162.37'; provider = 'Akamai International B.V.'; countryCode = 'NL'; city = ''; latitude = 52.4; longitude = 4.9; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '88.221.162.94'; provider = 'Akamai International B.V.'; countryCode = 'NL'; city = ''; latitude = 52.4; longitude = 4.9; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '88.221.163.196'; provider = 'Akamai International B.V.'; countryCode = 'NL'; city = ''; latitude = 52.4; longitude = 4.9; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '195.159.253.130'; provider = 'Globalconnect As'; countryCode = 'NO'; city = 'Langhus'; latitude = 59.9; longitude = 10.8; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '77.222.170.103'; provider = 'Eltele AS'; countryCode = 'NO'; city = 'Alta'; latitude = 59.9; longitude = 10.8; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '78.31.85.18'; provider = 'Telenor Norge AS'; countryCode = 'NO'; city = 'Andalsnes'; latitude = 59.9; longitude = 10.8; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '94.127.59.12'; provider = 'mnemonic AS'; countryCode = 'NO'; city = ''; latitude = 59.9; longitude = 10.8; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '94.127.59.14'; provider = 'mnemonic AS'; countryCode = 'NO'; city = ''; latitude = 59.9; longitude = 10.8; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '124.83.13.150'; provider = 'Philippine Long Distance Telep'; countryCode = 'PH'; city = 'Balingasag'; latitude = 14.6; longitude = 121; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '203.158.15.67'; provider = 'Unit 802 Orient Square Buildin'; countryCode = 'PH'; city = ''; latitude = 14.6; longitude = 121; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '203.177.52.229'; provider = 'Globe Telecoms'; countryCode = 'PH'; city = 'Andres Bonifacio'; latitude = 14.6; longitude = 121; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '210.1.81.40'; provider = 'Philippine Long Distance Telep'; countryCode = 'PH'; city = 'Mandaue City'; latitude = 14.6; longitude = 121; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '210.1.86.1'; provider = 'Philippine Long Distance Telep'; countryCode = 'PH'; city = 'Legazpi'; latitude = 14.6; longitude = 121; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '210.5.101.242'; provider = 'Philippine Long Distance Telep'; countryCode = 'PH'; city = 'Ozamiz'; latitude = 14.6; longitude = 121; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '118.103.239.33'; provider = 'Connect Communications'; countryCode = 'PK'; city = 'Karachi'; latitude = 24.9; longitude = 67; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '203.135.31.114'; provider = 'Pakistan Telecommunication Com'; countryCode = 'PK'; city = 'Gujrat'; latitude = 24.9; longitude = 67; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '195.3.204.225'; provider = 'TUCHA Sp. z o.o.'; countryCode = 'PL'; city = ''; latitude = 52.2; longitude = 21; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '77.45.111.51'; provider = 'Asta-net S.A.'; countryCode = 'PL'; city = 'Czarnkow'; latitude = 52.2; longitude = 21; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '77.65.176.110'; provider = 'ICT FUTURE Sp. z o.o.'; countryCode = 'PL'; city = 'Wroclaw'; latitude = 52.2; longitude = 21; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '80.87.39.34'; provider = 'INEA sp. z o.o.'; countryCode = 'PL'; city = 'Sompolno'; latitude = 52.2; longitude = 21; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '91.233.237.201'; provider = 'PROSAT s.c.'; countryCode = 'PL'; city = 'Kościan'; latitude = 52.2; longitude = 21; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '94.240.43.117'; provider = 'FHU PING'; countryCode = 'PL'; city = 'Warsaw'; latitude = 52.2; longitude = 21; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '94.46.175.93'; provider = 'Almouroltec Servicos De Inform'; countryCode = 'PT'; city = 'Leiria'; latitude = 38.7; longitude = -9.1; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '190.52.135.140'; provider = 'COMPANIA PARAGUAYA DE COMUNICA'; countryCode = 'PY'; city = 'San Lorenzo'; latitude = -25.3; longitude = -57.6; region = 'samer'; anycast = $false }
    [pscustomobject]@{ ip = '201.217.57.148'; provider = 'COMPANIA PARAGUAYA DE COMUNICA'; countryCode = 'PY'; city = 'Asunción'; latitude = -25.3; longitude = -57.6; region = 'samer'; anycast = $false }
    [pscustomobject]@{ ip = '212.146.97.154'; provider = 'GTS Telecom SRL'; countryCode = 'RO'; city = 'Bucharest'; latitude = 44.4; longitude = 26.1; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '5.2.196.93'; provider = 'RCS & RDS'; countryCode = 'RO'; city = 'Cluj-Napoca'; latitude = 44.4; longitude = 26.1; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '80.96.177.217'; provider = 'Vodafone Romania S.A.'; countryCode = 'RO'; city = ''; latitude = 44.4; longitude = 26.1; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '89.42.219.106'; provider = 'ROMARG SRL'; countryCode = 'RO'; city = ''; latitude = 44.4; longitude = 26.1; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '94.52.89.226'; provider = 'Nextgen Communications Srl'; countryCode = 'RO'; city = 'Giurgiu'; latitude = 44.4; longitude = 26.1; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '93.87.119.162'; provider = 'TELEKOM SRBIJA a.d.'; countryCode = 'RS'; city = ''; latitude = 44.8; longitude = 20.5; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '93.87.127.66'; provider = 'TELEKOM SRBIJA a.d.'; countryCode = 'RS'; city = 'Opstina Arandelovac'; latitude = 44.8; longitude = 20.5; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '217.150.35.129'; provider = 'Joint Stock Company TransTeleC'; countryCode = 'RU'; city = 'Rostov-on-Don'; latitude = 55.8; longitude = 37.6; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '5.164.31.60'; provider = 'JSC ER-Telecom Holding'; countryCode = 'RU'; city = 'Tula'; latitude = 55.8; longitude = 37.6; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '5.188.42.199'; provider = 'OOO Network of data-centers Se'; countryCode = 'RU'; city = 'St Petersburg'; latitude = 55.8; longitude = 37.6; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '62.76.62.76'; provider = 'Joint-stock company Internet E'; countryCode = 'RU'; city = ''; latitude = 55.8; longitude = 37.6; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '91.223.120.25'; provider = 'Sibirskie Innovacionnye Sistem'; countryCode = 'RU'; city = ''; latitude = 55.8; longitude = 37.6; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '192.165.252.20'; provider = 'Fiberaccessbolaget i Sverige A'; countryCode = 'SE'; city = 'Ängelholm'; latitude = 59.3; longitude = 18.1; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '217.119.160.99'; provider = 'Tele2 SWIPnet'; countryCode = 'SE'; city = 'Stockholm'; latitude = 59.3; longitude = 18.1; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '116.12.172.241'; provider = 'SingNet'; countryCode = 'SG'; city = 'Singapore'; latitude = 1.35; longitude = 103.8; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '119.75.28.242'; provider = 'SingNet'; countryCode = 'SG'; city = ''; latitude = 1.35; longitude = 103.8; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '124.66.128.198'; provider = 'SingNet'; countryCode = 'SG'; city = ''; latitude = 1.35; longitude = 103.8; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '128.106.52.161'; provider = 'SingNet'; countryCode = 'SG'; city = ''; latitude = 1.35; longitude = 103.8; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '151.192.60.134'; provider = 'SingNet'; countryCode = 'SG'; city = ''; latitude = 1.35; longitude = 103.8; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '180.255.3.49'; provider = 'SingNet'; countryCode = 'SG'; city = ''; latitude = 1.35; longitude = 103.8; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '193.2.246.9'; provider = 'ARNES'; countryCode = 'SI'; city = 'Zgornje Gorje'; latitude = 46.1; longitude = 14.5; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '89.233.118.207'; provider = 'T-2 d.o.o.'; countryCode = 'SI'; city = 'Brezovica pri Ljubljani'; latitude = 46.1; longitude = 14.5; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '93.103.221.171'; provider = 'T-2 d.o.o.'; countryCode = 'SI'; city = 'Kamenica'; latitude = 46.1; longitude = 14.5; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '1.1.188.104'; provider = 'TOT Public Company Limited'; countryCode = 'TH'; city = 'Ban Phan Don'; latitude = 13.8; longitude = 100.5; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '110.77.149.172'; provider = 'CAT TELECOM Public Company Ltd'; countryCode = 'TH'; city = 'Samut Prakan'; latitude = 13.8; longitude = 100.5; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '122.155.213.7'; provider = 'The Communication Authoity of'; countryCode = 'TH'; city = ''; latitude = 13.8; longitude = 100.5; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '159.192.105.164'; provider = 'CAT TELECOM Public Company Ltd'; countryCode = 'TH'; city = ''; latitude = 13.8; longitude = 100.5; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '159.192.142.29'; provider = 'CAT TELECOM Public Company Ltd'; countryCode = 'TH'; city = 'Ban Dan Noen Sung'; latitude = 13.8; longitude = 100.5; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '202.129.59.69'; provider = 'The Communication Authoity of'; countryCode = 'TH'; city = 'Si Khoraphum'; latitude = 13.8; longitude = 100.5; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '85.9.129.36'; provider = 'Tacom LLC'; countryCode = 'TJ'; city = 'Dushanbe'; latitude = 38.6; longitude = 68.8; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '85.9.129.38'; provider = 'Tacom LLC'; countryCode = 'TJ'; city = 'Dushanbe'; latitude = 38.6; longitude = 68.8; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '196.203.125.132'; provider = 'EL-Khawarizmi'; countryCode = 'TN'; city = ''; latitude = 36.8; longitude = 10.2; region = 'africa'; anycast = $false }
    [pscustomobject]@{ ip = '196.203.125.133'; provider = 'EL-Khawarizmi'; countryCode = 'TN'; city = ''; latitude = 36.8; longitude = 10.2; region = 'africa'; anycast = $false }
    [pscustomobject]@{ ip = '176.235.135.204'; provider = 'Superonline Iletisim Hizmetler'; countryCode = 'TR'; city = ''; latitude = 41; longitude = 29; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '195.21.58.113'; provider = 'GTT Communications Inc.'; countryCode = 'TR'; city = ''; latitude = 41; longitude = 29; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '31.7.37.37'; provider = 'Teknet Yazlim Ve Bilgisayar Te'; countryCode = 'TR'; city = 'Antalya'; latitude = 41; longitude = 29; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '85.99.234.230'; provider = 'Turk Telekom'; countryCode = 'TR'; city = 'Istanbul'; latitude = 41; longitude = 29; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '196.3.132.154'; provider = 'Telecommunication Services of'; countryCode = 'TT'; city = ''; latitude = 10.7; longitude = -61.5; region = 'namer'; anycast = $false }
    [pscustomobject]@{ ip = '118.99.210.36'; provider = 'SaveCom Internation Inc.'; countryCode = 'TW'; city = 'Hsinchu County'; latitude = 25; longitude = 121.6; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '168.95.1.1'; provider = 'Data Communication Business Gr'; countryCode = 'TW'; city = ''; latitude = 25; longitude = 121.6; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '220.135.28.237'; provider = 'Data Communication Business Gr'; countryCode = 'TW'; city = 'Taipei'; latitude = 25; longitude = 121.6; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '59.125.246.99'; provider = 'Data Communication Business Gr'; countryCode = 'TW'; city = 'Tainan City'; latitude = 25; longitude = 121.6; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '60.250.158.126'; provider = 'Data Communication Business Gr'; countryCode = 'TW'; city = 'Taipei'; latitude = 25; longitude = 121.6; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '60.250.159.76'; provider = 'Data Communication Business Gr'; countryCode = 'TW'; city = 'Taipei'; latitude = 25; longitude = 121.6; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '176.104.57.223'; provider = 'UnderNet LLC'; countryCode = 'UA'; city = 'Irpin'; latitude = 50.5; longitude = 30.5; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '176.104.59.191'; provider = 'UnderNet LLC'; countryCode = 'UA'; city = 'Kyiv'; latitude = 50.5; longitude = 30.5; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '176.98.80.97'; provider = 'TOV TV&Radio Company TIM'; countryCode = 'UA'; city = 'Uman'; latitude = 50.5; longitude = 30.5; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '178.158.234.89'; provider = 'Maximum-Net LLC'; countryCode = 'UA'; city = 'Vyshneve'; latitude = 50.5; longitude = 30.5; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '95.67.81.143'; provider = 'Cosmonova LLC'; countryCode = 'UA'; city = 'Kyiv'; latitude = 50.5; longitude = 30.5; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '151.196.0.37'; provider = 'UUNET'; countryCode = 'US'; city = 'Crofton'; latitude = 38.9; longitude = -77; region = 'namer'; anycast = $false }
    [pscustomobject]@{ ip = '151.197.0.37'; provider = 'UUNET'; countryCode = 'US'; city = ''; latitude = 38.9; longitude = -77; region = 'namer'; anycast = $false }
    [pscustomobject]@{ ip = '151.197.0.38'; provider = 'UUNET'; countryCode = 'US'; city = 'Philadelphia'; latitude = 38.9; longitude = -77; region = 'namer'; anycast = $false }
    [pscustomobject]@{ ip = '151.201.0.38'; provider = 'UUNET'; countryCode = 'US'; city = ''; latitude = 38.9; longitude = -77; region = 'namer'; anycast = $false }
    [pscustomobject]@{ ip = '156.154.71.2'; provider = 'SECURITYSERVICES'; countryCode = 'US'; city = ''; latitude = 38.9; longitude = -77; region = 'namer'; anycast = $false }
    [pscustomobject]@{ ip = '165.87.201.244'; provider = 'ATT-INTERNET4'; countryCode = 'US'; city = ''; latitude = 38.9; longitude = -77; region = 'namer'; anycast = $false }
    [pscustomobject]@{ ip = '80.80.218.218'; provider = 'LLC texnoprosistem'; countryCode = 'UZ'; city = 'Tashkent'; latitude = 41.3; longitude = 69.2; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '103.137.156.3'; provider = 'Vietnam News Agency'; countryCode = 'VN'; city = ''; latitude = 21; longitude = 105.8; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '103.239.32.36'; provider = 'Vietnam National Coaland Miner'; countryCode = 'VN'; city = ''; latitude = 21; longitude = 105.8; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '123.30.27.24'; provider = 'VNPT Corp'; countryCode = 'VN'; city = 'Thanh Hóa'; latitude = 21; longitude = 105.8; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '125.234.238.3'; provider = 'Viettel Group'; countryCode = 'VN'; city = 'Hanoi'; latitude = 21; longitude = 105.8; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '202.6.96.4'; provider = 'Vietnam News Agency'; countryCode = 'VN'; city = ''; latitude = 21; longitude = 105.8; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '202.78.224.129'; provider = 'Quang Trung Software City Deve'; countryCode = 'VN'; city = 'Ho Chi Minh City'; latitude = 21; longitude = 105.8; region = 'asia'; anycast = $false }
    [pscustomobject]@{ ip = '82.114.79.146'; provider = 'Kujtesa Net Sh.p.k.'; countryCode = 'XK'; city = 'Pristina'; latitude = 42.7; longitude = 21.2; region = 'europe'; anycast = $false }
    [pscustomobject]@{ ip = '105.243.213.211'; provider = 'Vodacom-VB'; countryCode = 'ZA'; city = 'Pretoria'; latitude = -26.2; longitude = 28; region = 'africa'; anycast = $false }
    [pscustomobject]@{ ip = '105.255.121.94'; provider = 'Vodacom-VB'; countryCode = 'ZA'; city = 'George'; latitude = -26.2; longitude = 28; region = 'africa'; anycast = $false }
    [pscustomobject]@{ ip = '196.216.134.71'; provider = 'Hero-Telecoms'; countryCode = 'ZA'; city = 'Mafikeng'; latitude = -26.2; longitude = 28; region = 'africa'; anycast = $false }
    [pscustomobject]@{ ip = '41.0.170.154'; provider = 'Vodacom-VB'; countryCode = 'ZA'; city = 'Nelspruit'; latitude = -26.2; longitude = 28; region = 'africa'; anycast = $false }
    [pscustomobject]@{ ip = '41.185.21.252'; provider = 'ZA-1-Grid'; countryCode = 'ZA'; city = ''; latitude = -26.2; longitude = 28; region = 'africa'; anycast = $false }
    [pscustomobject]@{ ip = '41.23.184.111'; provider = 'Vodacom-VB'; countryCode = 'ZA'; city = 'Johannesburg'; latitude = -26.2; longitude = 28; region = 'africa'; anycast = $false }
    [pscustomobject]@{ ip = '41.60.129.80'; provider = 'realtime-as'; countryCode = 'ZM'; city = ''; latitude = -15.4; longitude = 28.3; region = 'africa'; anycast = $false }
  )

  $override = [string]$env:ACS_PROPAGATION_RESOLVERS
  if ([string]::IsNullOrWhiteSpace($override)) { return $builtIn }

  # NOTE: use ::new() rather than `New-Object ...List[object]` throughout this
  # file. On PowerShell 7.6 / .NET 10 a List[object] built with New-Object throws
  # "Argument types do not match" the moment it is wrapped in @( ... ).
  $custom = [System.Collections.Generic.List[object]]::new()
  foreach ($entry in ($override -split ';')) {
    $parts = ($entry -split '\|')
    if ($parts.Count -lt 1) { continue }
    $ip = ([string]$parts[0]).Trim()
    if ([string]::IsNullOrWhiteSpace($ip)) { continue }

    $lat = 0.0
    $lon = 0.0
    if ($parts.Count -gt 4) { [void][double]::TryParse(([string]$parts[4]).Trim(), [ref]$lat) }
    if ($parts.Count -gt 5) { [void][double]::TryParse(([string]$parts[5]).Trim(), [ref]$lon) }

    $custom.Add([pscustomobject]@{
      ip          = $ip
      provider    = if ($parts.Count -gt 1 -and -not [string]::IsNullOrWhiteSpace($parts[1])) { ([string]$parts[1]).Trim() } else { $ip }
      countryCode = if ($parts.Count -gt 2) { ([string]$parts[2]).Trim().ToUpperInvariant() } else { '' }
      city        = if ($parts.Count -gt 3) { ([string]$parts[3]).Trim() } else { '' }
      latitude    = $lat
      longitude   = $lon
      region      = if ($parts.Count -gt 6 -and -not [string]::IsNullOrWhiteSpace($parts[6])) { ([string]$parts[6]).Trim().ToLowerInvariant() } else { 'global' }
      anycast     = ($parts.Count -gt 7 -and ([string]$parts[7]).Trim() -eq '1')
    })
  }

  if ($custom.Count -eq 0) { return $builtIn }
  return @($custom)
}

# ---- Resolver health cache -------------------------------------------------
#
# The standalone DNS Propagation Checker keeps a `PublicDns_VettedResolvers.json`
# file listing every resolver that passed a UDP+TCP probe, refreshed on a 24h
# timer, and uses it to avoid wasting a check slot on a dead server. We need the
# same effect without adding a state file to a single-script app, so health is
# remembered in-process instead: every fan-out records which resolvers answered,
# and selection prefers proven-good ones on the next request.
#
# Entries expire (ACS_PROPAGATION_HEALTH_TTL_MIN, default 30) so a resolver that
# was down temporarily gets another chance. The dictionary lives on the global
# scope and is shared into the request runspace pool by 22-RunspaceSetup.ps1 so
# every worker sees the same view.
if (-not $global:AcsPropagationHealth) {
  $global:AcsPropagationHealth = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
}

function Get-DnsPropagationHealthTtlMinutes {
  $ttl = 30
  $parsed = 0
  if ([int]::TryParse([string]$env:ACS_PROPAGATION_HEALTH_TTL_MIN, [ref]$parsed) -and $parsed -gt 0) {
    $ttl = [Math]::Min(1440, $parsed)
  }
  return $ttl
}

# Returns $true (known good), $false (known bad), or $null (unknown / expired).
#
# NOTE: the dictionary is referenced UNQUALIFIED ($AcsPropagationHealth, not
# $global:...) because 22-RunspaceSetup.ps1 injects it into each worker runspace
# as a session-state variable at that runspace's global scope -- exactly how
# $AcsRateLimitStore is handled. Using the global: prefix would resolve to an
# empty variable inside workers and silently disable the cache.
function Get-DnsPropagationHealthState {
  param([string]$Ip)

  if (-not $AcsPropagationHealth) { return $null }
  $key = ([string]$Ip).Trim()
  if ([string]::IsNullOrWhiteSpace($key)) { return $null }

  $entry = $null
  if (-not $AcsPropagationHealth.TryGetValue($key, [ref]$entry)) { return $null }
  if ($null -eq $entry) { return $null }

  try {
    if (([DateTime]::UtcNow - [DateTime]$entry.atUtc).TotalMinutes -gt (Get-DnsPropagationHealthTtlMinutes)) { return $null }
  } catch { return $null }

  return [bool]$entry.healthy
}

function Set-DnsPropagationHealthState {
  param([string]$Ip, [bool]$Healthy)

  if (-not $AcsPropagationHealth) { return }
  $key = ([string]$Ip).Trim()
  if ([string]::IsNullOrWhiteSpace($key)) { return }

  # Bound the dictionary: the catalog is finite, but an operator override or a
  # very long-lived process could otherwise grow it without limit.
  if ($AcsPropagationHealth.Count -gt 5000) {
    foreach ($stale in @($AcsPropagationHealth.Keys)) {
      $removed = $null
      $null = $AcsPropagationHealth.TryRemove($stale, [ref]$removed)
    }
  }

  $AcsPropagationHealth[$key] = @{ healthy = $Healthy; atUtc = [DateTime]::UtcNow }
}

# Parse operator- or user-supplied resolver addresses into catalog-shaped objects.
#
# Accepted per entry (newline, comma or semicolon separated):
#   1.2.3.4
#   1.2.3.4 My office resolver
#   1.2.3.4|My office resolver
#
# SECURITY: this is the one place a *user* (not just the operator) can influence
# which sockets we open, so every address must parse as a public IPv4 literal --
# hostnames are refused outright so nothing is resolved on the user's behalf, and
# Test-IsPublicIpAddress blocks loopback/private/link-local/CGNAT targets.
function ConvertFrom-DnsPropagationResolverInput {
  param(
    [string]$Text,
    [int]$MaxEntries = 100
  )

  $parsed = [System.Collections.Generic.List[object]]::new()
  if ([string]::IsNullOrWhiteSpace($Text)) { return $parsed.ToArray() }

  $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($rawEntry in ($Text -split '[\r\n,;]+')) {
    if ($parsed.Count -ge $MaxEntries) { break }
    $entry = ([string]$rawEntry).Trim()
    if ([string]::IsNullOrWhiteSpace($entry)) { continue }

    $ip = $entry
    $label = ''
    $sepIndex = $entry.IndexOfAny([char[]]@('|', ' ', "`t"))
    if ($sepIndex -gt 0) {
      $ip = $entry.Substring(0, $sepIndex).Trim()
      $label = $entry.Substring($sepIndex + 1).Trim()
    }

    $parsedIp = $null
    if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$parsedIp)) { continue }
    if ($parsedIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { continue }
    if (-not (Test-IsPublicIpAddress -IpAddress $ip)) { continue }
    if (-not $seen.Add($ip)) { continue }

    if ($label.Length -gt 40) { $label = $label.Substring(0, 40).Trim() }
    if ([string]::IsNullOrWhiteSpace($label)) { $label = $ip }

    # No coordinates: we cannot geolocate an arbitrary address, and inventing one
    # would put a misleading pin on the map. Null lat/lon keeps these out of the
    # map rollup while still showing them in the per-resolver detail list.
    $parsed.Add([pscustomobject]@{
      ip          = $ip
      provider    = $label
      countryCode = ''
      city        = ''
      latitude    = $null
      longitude   = $null
      region      = 'custom'
      anycast     = $false
    })
  }

  return $parsed.ToArray()
}

# Pick the resolvers to query for one propagation run.
#
# The selection is deliberately *balanced*: we round-robin across the requested
# regions so a small MaxResolvers budget still produces a geographically spread
# sample instead of, say, five Chinese resolvers. Within a region the catalog
# order is preserved so results are stable and reproducible across runs (the
# card would otherwise flicker between lookups for no reason) -- except that
# resolvers we recently saw fail sink to the bottom of their region bucket, so a
# large request is not silently padded out with servers already known to be dead.
function Select-DnsPropagationResolvers {
  param(
    [string[]]$Regions = @(),
    [int]$MaxResolvers = 25
  )

  $catalog = @(Get-DnsPropagationResolverCatalog)

  # Only keep entries whose IP literal is public and parseable. This is the SSRF
  # guard for the operator-supplied ACS_PROPAGATION_RESOLVERS override.
  $usable = [System.Collections.Generic.List[object]]::new()
  foreach ($item in $catalog) {
    if ($null -eq $item) { continue }
    $ip = ([string]$item.ip).Trim()
    $parsedIp = $null
    if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$parsedIp)) { continue }
    # IPv4 only: many hosts (and most containers) have no working IPv6 path, and
    # a v6-only resolver would show up as a false "unavailable" data point.
    if ($parsedIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { continue }
    if (-not (Test-IsPublicIpAddress -IpAddress $ip)) { continue }
    $usable.Add($item)
  }

  $wanted = @($Regions | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() })
  if ($wanted.Count -gt 0) {
    $filtered = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $usable) {
      if ($wanted -contains ([string]$item.region).ToLowerInvariant()) { $filtered.Add($item) }
    }
    $usable = $filtered
  }

  if ($usable.Count -eq 0) { return @() }
  if ($MaxResolvers -le 0 -or $MaxResolvers -ge $usable.Count) { return $usable.ToArray() }

  # Group by region (preserving catalog order inside each group), then take one
  # from each group in turn until the budget is spent.
  $groups = [ordered]@{}
  foreach ($item in $usable) {
    $key = ([string]$item.region).ToLowerInvariant()
    if (-not $groups.Contains($key)) { $groups[$key] = [System.Collections.Generic.List[object]]::new() }
    $groups[$key].Add($item)
  }

  # Within each region, float resolvers we know answered recently to the front and
  # sink ones we know are dead. Unknown/expired entries stay in catalog order in
  # between, so a fresh process still walks the list deterministically.
  foreach ($key in @($groups.Keys)) {
    $bucket = $groups[$key]
    $known = [System.Collections.Generic.List[object]]::new()
    $unknown = [System.Collections.Generic.List[object]]::new()
    $dead = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $bucket) {
      $health = Get-DnsPropagationHealthState -Ip ([string]$item.ip)
      if ($health -eq $true) { $known.Add($item) }
      elseif ($health -eq $false) { $dead.Add($item) }
      else { $unknown.Add($item) }
    }
    $ordered = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $known) { $ordered.Add($item) }
    foreach ($item in $unknown) { $ordered.Add($item) }
    foreach ($item in $dead) { $ordered.Add($item) }
    $groups[$key] = $ordered
  }

  $selected = [System.Collections.Generic.List[object]]::new()
  $index = 0
  while ($selected.Count -lt $MaxResolvers) {
    $addedThisPass = $false
    foreach ($key in @($groups.Keys)) {
      if ($selected.Count -ge $MaxResolvers) { break }
      $bucket = $groups[$key]
      if ($index -lt $bucket.Count) {
        $selected.Add($bucket[$index])
        $addedThisPass = $true
      }
    }
    if (-not $addedThisPass) { break }
    $index++
  }

  return $selected.ToArray()
}

# Read a (possibly compressed) DNS name starting at $Offset.
#
# Returns a hashtable @{ name = 'label.label'; next = <offset after the name> }.
# `next` is the offset immediately after the name AS ENCODED AT $Offset, so a
# compression pointer consumes exactly 2 bytes even though the name continues
# elsewhere in the message. A hop budget defends against pointer loops in a
# malformed/hostile response.
function Read-DnsNameFromBuffer {
  param([byte[]]$Buffer, [int]$Offset)

  $labels = New-Object System.Collections.Generic.List[string]
  $pos = $Offset
  $next = -1
  $hops = 0

  while ($true) {
    if ($pos -lt 0 -or $pos -ge $Buffer.Length) { break }
    $len = [int]$Buffer[$pos]

    if ($len -eq 0) {
      if ($next -lt 0) { $next = $pos + 1 }
      break
    }

    if (($len -band 0xC0) -eq 0xC0) {
      if (($pos + 1) -ge $Buffer.Length) { break }
      if ($next -lt 0) { $next = $pos + 2 }
      $hops++
      if ($hops -gt 24) { break }
      $pos = ((($len -band 0x3F) -shl 8) -bor [int]$Buffer[$pos + 1])
      continue
    }

    if ($len -gt 63) { break }
    $start = $pos + 1
    if (($start + $len) -gt $Buffer.Length) { break }
    $labels.Add([System.Text.Encoding]::ASCII.GetString($Buffer, $start, $len))
    $pos = $start + $len
  }

  if ($next -lt 0) { $next = $pos }
  return @{ name = ($labels -join '.'); next = $next }
}

# Convert one resource record's RDATA into the display string we compare across
# resolvers. Unsupported types fall back to lowercase hex so a mismatch is still
# detectable even when we cannot pretty-print the payload.
function ConvertFrom-DnsPropagationRdata {
  param(
    [byte[]]$Buffer,
    [int]$Type,
    [int]$RdataOffset,
    [int]$RdLength
  )

  if ($RdLength -le 0 -or ($RdataOffset + $RdLength) -gt $Buffer.Length) { return $null }
  $end = $RdataOffset + $RdLength

  switch ($Type) {
    1 {
      # A
      if ($RdLength -ne 4) { return $null }
      return ('{0}.{1}.{2}.{3}' -f $Buffer[$RdataOffset], $Buffer[$RdataOffset + 1], $Buffer[$RdataOffset + 2], $Buffer[$RdataOffset + 3])
    }
    28 {
      # AAAA -- let IPAddress do the canonical (compressed) formatting.
      if ($RdLength -ne 16) { return $null }
      $raw = New-Object byte[] 16
      [Array]::Copy($Buffer, $RdataOffset, $raw, 0, 16)
      try { return ([System.Net.IPAddress]::new($raw)).ToString() } catch { return $null }
    }
    16 {
      # TXT: one or more <character-string>s, concatenated with no separator
      # (RFC 7208) so a split long record reassembles into the original value.
      $sb = New-Object System.Text.StringBuilder
      $p = $RdataOffset
      while ($p -lt $end) {
        $clen = [int]$Buffer[$p]; $p++
        if (($p + $clen) -gt $end) { break }
        if ($clen -gt 0) {
          [void]$sb.Append([System.Text.Encoding]::UTF8.GetString($Buffer, $p, $clen))
          $p += $clen
        }
      }
      $value = $sb.ToString().Trim()
      if ([string]::IsNullOrWhiteSpace($value)) { return $null }
      return $value
    }
    15 {
      # MX: 16-bit preference followed by the exchange name.
      if ($RdLength -lt 3) { return $null }
      $pref = (([int]$Buffer[$RdataOffset]) -shl 8) -bor [int]$Buffer[$RdataOffset + 1]
      $parsed = Read-DnsNameFromBuffer -Buffer $Buffer -Offset ($RdataOffset + 2)
      if ([string]::IsNullOrWhiteSpace($parsed.name)) { return $null }
      return ('{0} {1}' -f $pref, $parsed.name.ToLowerInvariant())
    }
    257 {
      # CAA: flags(1) tag-length(1) tag value
      if ($RdLength -lt 3) { return $null }
      $flags = [int]$Buffer[$RdataOffset]
      $tagLen = [int]$Buffer[$RdataOffset + 1]
      $tagStart = $RdataOffset + 2
      if (($tagStart + $tagLen) -gt $end) { return $null }
      $tag = [System.Text.Encoding]::ASCII.GetString($Buffer, $tagStart, $tagLen)
      $valStart = $tagStart + $tagLen
      $val = ''
      if ($valStart -lt $end) { $val = [System.Text.Encoding]::UTF8.GetString($Buffer, $valStart, ($end - $valStart)) }
      return ('{0} {1} "{2}"' -f $flags, $tag, $val)
    }
    6 {
      # SOA: mname rname serial refresh retry expire minimum. Only the primary
      # nameserver and serial are worth comparing across resolvers -- a serial
      # difference is the clearest signal that a zone transfer is still in flight.
      $mname = Read-DnsNameFromBuffer -Buffer $Buffer -Offset $RdataOffset
      $rname = Read-DnsNameFromBuffer -Buffer $Buffer -Offset $mname.next
      $p = $rname.next
      if (($p + 4) -gt $end) { return $null }
      $serial = ((([long]$Buffer[$p]) -shl 24) -bor (([long]$Buffer[$p + 1]) -shl 16) -bor (([long]$Buffer[$p + 2]) -shl 8) -bor ([long]$Buffer[$p + 3]))
      return ('{0} {1} {2}' -f $mname.name.ToLowerInvariant(), $rname.name.ToLowerInvariant(), $serial)
    }
    default {
      # NS (2), CNAME (5), PTR (12) and anything else name-shaped.
      if ($Type -eq 2 -or $Type -eq 5 -or $Type -eq 12) {
        $parsed = Read-DnsNameFromBuffer -Buffer $Buffer -Offset $RdataOffset
        if ([string]::IsNullOrWhiteSpace($parsed.name)) { return $null }
        return $parsed.name.ToLowerInvariant()
      }
      $hex = New-Object System.Text.StringBuilder
      for ($i = $RdataOffset; $i -lt $end; $i++) { [void]$hex.Append($Buffer[$i].ToString('x2')) }
      return $hex.ToString()
    }
  }
}

# Build a recursive DNS query packet for $Name / $TypeCode.
#
# RD (recursion desired) is 1 here -- unlike the authoritative probe in
# 16c-NameserverChecks.ps1 we WANT each public resolver's own recursive view,
# cache and all, because that is exactly what a real client (and Azure) sees.
# An EDNS0 OPT record advertises a 4096-byte UDP payload so large TXT sets are
# not truncated.
function New-DnsPropagationQueryPacket {
  param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][int]$TypeCode,
    [Parameter(Mandatory = $true)][int]$TransactionId
  )

  $packet = New-Object System.Collections.Generic.List[byte]

  # ---- Header (12 bytes) ----
  $packet.Add([byte](($TransactionId -shr 8) -band 0xFF))
  $packet.Add([byte]($TransactionId -band 0xFF))
  $packet.Add([byte]0x01)                            # QR=0 Opcode=0 AA=0 TC=0 RD=1
  $packet.Add([byte]0x00)                            # RA=0 Z=0 RCODE=0
  $packet.Add([byte]0x00); $packet.Add([byte]0x01)   # QDCOUNT = 1
  $packet.Add([byte]0x00); $packet.Add([byte]0x00)   # ANCOUNT = 0
  $packet.Add([byte]0x00); $packet.Add([byte]0x00)   # NSCOUNT = 0
  $packet.Add([byte]0x00); $packet.Add([byte]0x01)   # ARCOUNT = 1 (the OPT record)

  # ---- Question ----
  foreach ($label in ($Name -split '\.')) {
    if ([string]::IsNullOrEmpty($label)) { continue }
    $labelBytes = [System.Text.Encoding]::ASCII.GetBytes($label)
    if ($labelBytes.Length -gt 63) { throw 'DNS label exceeds 63 octets.' }
    $packet.Add([byte]$labelBytes.Length)
    $packet.AddRange($labelBytes)
  }
  $packet.Add([byte]0)                                                   # root label
  $packet.Add([byte](($TypeCode -shr 8) -band 0xFF))
  $packet.Add([byte]($TypeCode -band 0xFF))                              # QTYPE
  $packet.Add([byte]0x00); $packet.Add([byte]0x01)                       # QCLASS = IN

  # ---- Additional: EDNS0 OPT (RFC 6891) ----
  $packet.Add([byte]0x00)                            # NAME = root
  $packet.Add([byte]0x00); $packet.Add([byte]0x29)   # TYPE = 41 (OPT)
  $packet.Add([byte]0x10); $packet.Add([byte]0x00)   # CLASS = 4096 UDP payload size
  $packet.Add([byte]0x00); $packet.Add([byte]0x00)   # extended RCODE + version
  $packet.Add([byte]0x00); $packet.Add([byte]0x00)   # flags (DO=0)
  $packet.Add([byte]0x00); $packet.Add([byte]0x00)   # RDLENGTH = 0

  return , ($packet.ToArray())
}

# Parse a DNS response into @{ rcode; rcodeLabel; truncated; answers[] }.
# Answers are filtered to the requested QTYPE so a CNAME chain returned
# alongside an A lookup does not pollute the comparison, EXCEPT when the caller
# asked for CNAME itself.
function Read-DnsPropagationResponse {
  param(
    [byte[]]$Buffer,
    [int]$TransactionId,
    [int]$TypeCode
  )

  $parsed = @{ rcode = $null; rcodeLabel = $null; truncated = $false; answers = @(); error = $null }

  if ($null -eq $Buffer -or $Buffer.Length -lt 12) {
    $parsed.error = 'Short DNS response.'
    return $parsed
  }

  # Cast to [int] BEFORE shifting: PowerShell's -shl on a [byte] truncates back
  # to 8 bits, silently zeroing the high half of every 16-bit field.
  $respId = ([int]$Buffer[0] -shl 8) -bor [int]$Buffer[1]
  if ($respId -ne $TransactionId) {
    $parsed.error = 'DNS transaction ID mismatch.'
    return $parsed
  }

  $parsed.truncated = (($Buffer[2] -band 0x02) -ne 0)
  $rcode = ($Buffer[3] -band 0x0F)
  $parsed.rcode = $rcode
  $parsed.rcodeLabel = switch ($rcode) {
    0 { 'NOERROR' }
    1 { 'FORMERR' }
    2 { 'SERVFAIL' }
    3 { 'NXDOMAIN' }
    4 { 'NOTIMP' }
    5 { 'REFUSED' }
    default { "RCODE $rcode" }
  }

  $qdCount = ([int]$Buffer[4] -shl 8) -bor [int]$Buffer[5]
  $anCount = ([int]$Buffer[6] -shl 8) -bor [int]$Buffer[7]

  # Skip the question section.
  $offset = 12
  for ($q = 0; $q -lt $qdCount; $q++) {
    $name = Read-DnsNameFromBuffer -Buffer $Buffer -Offset $offset
    $offset = $name.next + 4   # QTYPE + QCLASS
  }

  $answers = New-Object System.Collections.Generic.List[string]
  for ($a = 0; $a -lt $anCount; $a++) {
    if ($offset -ge $Buffer.Length) { break }
    $owner = Read-DnsNameFromBuffer -Buffer $Buffer -Offset $offset
    $offset = $owner.next
    if (($offset + 10) -gt $Buffer.Length) { break }

    $type = ([int]$Buffer[$offset] -shl 8) -bor [int]$Buffer[$offset + 1]
    $offset += 8   # TYPE (2) + CLASS (2) + TTL (4)
    $rdLength = ([int]$Buffer[$offset] -shl 8) -bor [int]$Buffer[$offset + 1]
    $offset += 2
    if (($offset + $rdLength) -gt $Buffer.Length) { break }

    if ($type -eq $TypeCode) {
      $value = ConvertFrom-DnsPropagationRdata -Buffer $Buffer -Type $type -RdataOffset $offset -RdLength $rdLength
      if (-not [string]::IsNullOrWhiteSpace($value)) { $answers.Add($value) }
    }

    $offset += $rdLength
  }

  # Sorted so two resolvers returning the same record set in a different order
  # (round-robin rotation is standard) still produce an identical signature.
  $parsed.answers = @($answers | Sort-Object)
  return $parsed
}

# Recover truncated (TC=1) answers by re-asking the affected resolvers over TCP,
# concurrently.
#
# EDNS0 keeps truncation rare, but domains with very large TXT sets (dozens of
# verification tokens) still overflow a 4096-byte UDP datagram. Retrying those
# sequentially would add one full timeout PER resolver to the request, so this
# uses the same non-blocking + [Socket]::Select pattern as the UDP fan-out:
# every connection is opened and driven forward in one loop, so the whole
# recovery pass costs about one timeout window no matter how many resolvers
# need it.
#
# TCP DNS frames the message with a 2-byte big-endian length prefix in both
# directions (RFC 1035 4.2.2), and TCP is a stream, so each socket accumulates
# bytes until the declared length has arrived.
#
# $Queries maps resolver IP -> query packet. Returns resolver IP -> response bytes
# for the resolvers that answered.
function Invoke-DnsPropagationTcpFanout {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Queries,
    [int]$TimeoutMs = 4000
  )

  $responses = @{}
  if ($Queries.Count -eq 0) { return $responses }

  $states = @{}       # socket -> per-connection state
  $sockets = [System.Collections.Generic.List[System.Net.Sockets.Socket]]::new()
  $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

  try {
    foreach ($ip in @($Queries.Keys)) {
      $parsedIp = $null
      if (-not [System.Net.IPAddress]::TryParse(([string]$ip).Trim(), [ref]$parsedIp)) { continue }

      $sock = $null
      try {
        $sock = New-Object System.Net.Sockets.Socket($parsedIp.AddressFamily, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
        $sock.Blocking = $false
        try {
          $sock.Connect((New-Object System.Net.IPEndPoint($parsedIp, 53)))
        } catch [System.Net.Sockets.SocketException] {
          # WouldBlock is the expected result of a non-blocking connect; the
          # socket becoming writable is what tells us the handshake finished.
          if ($_.Exception.SocketErrorCode -ne [System.Net.Sockets.SocketError]::WouldBlock) { throw }
        }
        # Re-assert non-blocking and add socket-level timeouts: every Send/Receive
        # below happens only after Select reports the socket ready, but these are
        # a hard backstop against a blocking call pinning the request thread.
        $sock.Blocking = $false
        $sock.ReceiveTimeout = $TimeoutMs
        $sock.SendTimeout = $TimeoutMs
        $sockets.Add($sock)
        $states[$sock] = @{
          ip        = [string]$ip
          query     = $Queries[$ip]
          connected = $false
          buffer    = [System.Collections.Generic.List[byte]]::new()
          expected  = -1
        }
      } catch {
        if ($sock) { try { $sock.Dispose() } catch { } }
      }
    }

    $chunk = New-Object byte[] 8192
    while ($states.Count -gt 0) {
      $remainingMs = $TimeoutMs - $stopwatch.ElapsedMilliseconds
      if ($remainingMs -le 0) { break }

      # Select() empties the lists it is handed, so rebuild them every pass.
      # Sockets still handshaking are watched for writability; connected ones
      # for readability.
      $writeList = New-Object System.Collections.ArrayList
      $readList = New-Object System.Collections.ArrayList
      $errorList = New-Object System.Collections.ArrayList
      foreach ($sock in $states.Keys) {
        if ($states[$sock].connected) { [void]$readList.Add($sock) } else { [void]$writeList.Add($sock) }
        [void]$errorList.Add($sock)
      }

      $waitMicroseconds = [int]([Math]::Min(500000, [Math]::Max(1000, $remainingMs * 1000)))
      # Pass the ArrayLists through plain variables. A $( if (...) { $list } )
      # subexpression would ENUMERATE the list and hand Select a fixed-size
      # object[] copy instead, so Select could not strip the not-ready sockets
      # and we would go on to Receive() from sockets with nothing to read.
      $readArg = $null
      if ($readList.Count -gt 0) { $readArg = $readList }
      $writeArg = $null
      if ($writeList.Count -gt 0) { $writeArg = $writeList }
      try {
        [System.Net.Sockets.Socket]::Select($readArg, $writeArg, $errorList, $waitMicroseconds)
      } catch {
        break
      }

      foreach ($sock in @($errorList)) {
        [void]$states.Remove($sock)
      }

      # Newly connected sockets: send the framed query.
      foreach ($sock in @($writeList)) {
        $state = $states[$sock]
        if ($null -eq $state -or $state.connected) { continue }
        try {
          $query = $state.query
          $framed = New-Object byte[] (2 + $query.Length)
          $framed[0] = [byte](($query.Length -shr 8) -band 0xFF)
          $framed[1] = [byte]($query.Length -band 0xFF)
          [Array]::Copy($query, 0, $framed, 2, $query.Length)
          [void]$sock.Send($framed)
          $state.connected = $true
        } catch {
          [void]$states.Remove($sock)
        }
      }

      # Readable sockets: accumulate until the declared message length arrives.
      foreach ($sock in @($readList)) {
        $state = $states[$sock]
        if ($null -eq $state) { continue }
        try {
          $received = $sock.Receive($chunk)
          if ($received -le 0) { [void]$states.Remove($sock); continue }
          for ($i = 0; $i -lt $received; $i++) { $state.buffer.Add($chunk[$i]) }

          if ($state.expected -lt 0 -and $state.buffer.Count -ge 2) {
            $state.expected = ([int]$state.buffer[0] -shl 8) -bor [int]$state.buffer[1]
            if ($state.expected -le 0 -or $state.expected -gt 65535) { [void]$states.Remove($sock); continue }
          }
          if ($state.expected -ge 0 -and $state.buffer.Count -ge ($state.expected + 2)) {
            $message = New-Object byte[] $state.expected
            $state.buffer.CopyTo(2, $message, 0, $state.expected)
            $responses[$state.ip] = $message
            [void]$states.Remove($sock)
          }
        } catch {
          [void]$states.Remove($sock)
        }
      }
    }
  } finally {
    foreach ($sock in $sockets) { try { $sock.Dispose() } catch { } }
    $stopwatch.Stop()
  }

  return $responses
}


# Query every resolver in $Resolvers concurrently and return the raw outcome for
# each one, keyed by resolver IP.
#
# HOW THE CONCURRENCY WORKS: we open one connected UDP socket per resolver and
# send every query before waiting for anything. Then we block in
# [Socket]::Select on the whole set, draining whichever sockets became readable,
# until either all resolvers answered or the deadline expires. The total wall
# time is therefore ~one timeout window no matter how many resolvers we query,
# and -- crucially -- no PowerShell code ever runs on more than one thread, so
# this is safe inside the shared request runspace pool.
#
# Returns a hashtable: ip -> @{ answers[]; rcode; rcodeLabel; transport; responseMs; error; truncated }
function Invoke-DnsPropagationFanout {
  param(
    [Parameter(Mandatory = $true)][object[]]$Resolvers,
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][int]$TypeCode,
    [int]$TimeoutMs = 4000
  )

  $outcomes = @{}
  if ($Resolvers.Count -eq 0) { return $outcomes }

  $pending = @{}          # socket -> state
  $sockets = [System.Collections.Generic.List[System.Net.Sockets.Socket]]::new()
  $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

  try {
    foreach ($resolver in $Resolvers) {
      $ip = ([string]$resolver.ip).Trim()
      $outcomes[$ip] = @{ answers = @(); rcode = $null; rcodeLabel = $null; transport = $null; responseMs = $null; error = 'No response from resolver (UDP timeout).'; truncated = $false; query = $null; txid = 0 }

      $parsedIp = $null
      if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$parsedIp)) {
        $outcomes[$ip].error = 'Invalid resolver IP.'
        continue
      }

      $txid = Get-Random -Minimum 1 -Maximum 65535
      $query = $null
      try {
        $query = New-DnsPropagationQueryPacket -Name $Name -TypeCode $TypeCode -TransactionId $txid
      } catch {
        $outcomes[$ip].error = 'Failed to build DNS query.'
        continue
      }
      $outcomes[$ip].query = $query
      $outcomes[$ip].txid = $txid

      $sock = $null
      try {
        $sock = New-Object System.Net.Sockets.Socket($parsedIp.AddressFamily, [System.Net.Sockets.SocketType]::Dgram, [System.Net.Sockets.ProtocolType]::Udp)
        $sock.Blocking = $false
        $sock.Connect((New-Object System.Net.IPEndPoint($parsedIp, 53)))
        [void]$sock.Send($query)
        $sockets.Add($sock)
        $pending[$sock] = @{ ip = $ip; txid = $txid; sentAtMs = $stopwatch.ElapsedMilliseconds }
      } catch {
        $outcomes[$ip].error = 'Could not send query to resolver.'
        if ($sock) { try { $sock.Dispose() } catch { } }
      }
    }

    # ---- Wait for answers on all sockets at once ----
    $deadlineMs = $TimeoutMs
    $buffer = New-Object byte[] 4096
    while ($pending.Count -gt 0) {
      $remainingMs = $deadlineMs - $stopwatch.ElapsedMilliseconds
      if ($remainingMs -le 0) { break }

      # Select() mutates the list it is given (leaving only ready sockets), so
      # rebuild it from the still-pending set on every iteration.
      $readList = New-Object System.Collections.ArrayList
      foreach ($sock in $pending.Keys) { [void]$readList.Add($sock) }

      # Cap the per-iteration wait so we re-evaluate the deadline regularly.
      $waitMicroseconds = [int]([Math]::Min(500000, [Math]::Max(1000, $remainingMs * 1000)))
      try {
        [System.Net.Sockets.Socket]::Select($readList, $null, $null, $waitMicroseconds)
      } catch {
        break
      }
      if ($readList.Count -eq 0) { continue }

      foreach ($sock in @($readList)) {
        $state = $pending[$sock]
        if ($null -eq $state) { continue }
        $ip = $state.ip
        try {
          $received = $sock.Receive($buffer)
          if ($received -gt 0) {
            $exact = New-Object byte[] $received
            [Array]::Copy($buffer, 0, $exact, 0, $received)
            $parsed = Read-DnsPropagationResponse -Buffer $exact -TransactionId $state.txid -TypeCode $TypeCode
            if ($parsed.error) {
              # A stray/mismatched datagram: keep waiting on this socket rather
              # than accepting an answer we cannot attribute to our query.
              continue
            }
            $outcomes[$ip].answers = @($parsed.answers)
            $outcomes[$ip].rcode = $parsed.rcode
            $outcomes[$ip].rcodeLabel = $parsed.rcodeLabel
            $outcomes[$ip].truncated = $parsed.truncated
            $outcomes[$ip].transport = 'udp'
            $outcomes[$ip].responseMs = [int]($stopwatch.ElapsedMilliseconds - $state.sentAtMs)
            $outcomes[$ip].error = $null
          }
        } catch {
          $outcomes[$ip].error = 'Resolver connection error.'
        }
        [void]$pending.Remove($sock)
      }
    }
  } finally {
    foreach ($sock in $sockets) { try { $sock.Dispose() } catch { } }
    $stopwatch.Stop()
  }

  # ---- Concurrent TCP recovery pass for truncated answers ----
  # A TC=1 answer is NOT "no record" -- it means the answer did not fit in the
  # UDP datagram. Re-ask over TCP (all affected resolvers at once) so a domain
  # with a very large TXT set is still measured accurately. Anything still
  # truncated afterwards is reported as such and excluded from the verdict
  # rather than being silently misread as a missing record.
  $tcpQueries = @{}
  foreach ($ip in @($outcomes.Keys)) {
    $outcome = $outcomes[$ip]
    if ($outcome.truncated -and $null -ne $outcome.query) { $tcpQueries[$ip] = $outcome.query }
  }
  if ($tcpQueries.Count -gt 0) {
    $tcpResponses = Invoke-DnsPropagationTcpFanout -Queries $tcpQueries -TimeoutMs $TimeoutMs
    foreach ($ip in @($tcpResponses.Keys)) {
      $outcome = $outcomes[$ip]
      if ($null -eq $outcome) { continue }
      $parsed = Read-DnsPropagationResponse -Buffer $tcpResponses[$ip] -TransactionId $outcome.txid -TypeCode $TypeCode
      if ($parsed.error) { continue }
      $outcome.answers = @($parsed.answers)
      $outcome.rcode = $parsed.rcode
      $outcome.rcodeLabel = $parsed.rcodeLabel
      $outcome.truncated = $parsed.truncated
      $outcome.transport = 'tcp'
      $outcome.error = $null
    }
  }

  # Drop the internal fields the caller does not need (and must not serialize).
  foreach ($ip in @($outcomes.Keys)) {
    $outcomes[$ip].Remove('query')
    $outcomes[$ip].Remove('txid')
  }

  return $outcomes
}

# Orchestrate the propagation check for $Domain.
#
# The verdict is CONSENSUS-based rather than expectation-based: we take the most
# common non-empty answer set across resolvers that actually responded and
# measure everyone else against it. That answers "has my change propagated?"
# without the user having to type in what they expect to see, while an optional
# -ExpectedValue substring lets them assert a specific record when they want to.
#
# Resolvers that did not respond at all are reported but deliberately EXCLUDED
# from the verdict. Public resolvers are frequently rate-limited or firewalled
# from a given network, and a flaky resolver must never turn a healthy domain
# into a FAIL.
#
# Returned payload (stable contract for the SPA):
#   domain, generatedAtUtc, checked, disabledReason, recordType, queryName
#   resolverCount / respondedCount / unavailableCount / answeredCount /
#   emptyCount / matchingCount / mismatchCount / errorCount
#   consensusAnswers[], distinctAnswerSets, propagationPercent
#   state    : 'propagated' | 'partial' | 'mismatch' | 'norecord' | 'unknown'
#   summary  : short server-side fallback sentence key
#   regions[], availableRegions[], results[], locations[]
function Get-DnsPropagationStatus {
  param(
    [Parameter(Mandatory = $true)][string]$Domain,
    [string]$RecordType = 'TXT',
    [string[]]$Regions = @(),
    [int]$MaxResolvers = 0,
    [int]$TimeoutMs = 0,
    [string]$ExpectedValue = '',
    [string]$CustomResolvers = '',
    [bool]$ValidateResolvers = $true
  )

  $d = ([string]$Domain).Trim().TrimEnd('.')
  $normalizedType = ([string]$RecordType).Trim().ToUpperInvariant()
  if ([string]::IsNullOrWhiteSpace($normalizedType)) { $normalizedType = 'TXT' }

  $status = [pscustomobject]@{
    domain             = $d
    generatedAtUtc     = ([DateTime]::UtcNow.ToString('o'))
    checked            = $true
    disabledReason     = $null
    recordType         = $normalizedType
    queryName          = $d
    expectedValue      = ([string]$ExpectedValue).Trim()
    expectedProvided   = (-not [string]::IsNullOrWhiteSpace($ExpectedValue))
    timeoutMs          = 0
    resolverCount      = 0
    requestedCount     = 0
    candidateCount     = 0
    validated          = $false
    usingCustom        = $false
    catalogCount       = 0
    respondedCount     = 0
    unavailableCount   = 0
    truncatedCount     = 0
    answeredCount      = 0
    emptyCount         = 0
    matchingCount      = 0
    mismatchCount      = 0
    errorCount         = 0
    consensusAnswers   = @()
    distinctAnswerSets = 0
    propagationPercent = 0
    state              = 'unknown'
    summary            = 'Unknown'
    error              = $null
    regions            = @()
    availableRegions   = @()
    results            = @()
    locations          = @()
  }

  if ([string]::IsNullOrWhiteSpace($d)) {
    $status.checked = $false
    $status.error = 'Missing domain.'
    return $status
  }

  # Operator opt-out for networks where outbound UDP/53 is undesirable or blocked.
  if (([string]$env:ACS_DISABLE_PROPAGATION_PROBE).Trim() -eq '1') {
    $status.checked = $false
    $status.summary = 'Disabled'
    $status.disabledReason = 'DNS propagation probe disabled by server configuration.'
    return $status
  }

  $typeCode = Get-DnsPropagationTypeCode -RecordType $normalizedType
  if ($typeCode -eq 0) {
    $status.checked = $false
    $status.error = 'Unsupported record type.'
    return $status
  }

  # ---- Bounded, tunable knobs (mirrors the website / nameserver / RBL checks) ----
  $defaultMax = 25
  $parsed = 0
  if ([int]::TryParse([string]$env:ACS_PROPAGATION_MAX_RESOLVERS, [ref]$parsed) -and $parsed -gt 0) {
    $defaultMax = [Math]::Min(100, $parsed)
  }
  $effectiveMax = if ($MaxResolvers -gt 0) { [Math]::Min(100, $MaxResolvers) } else { $defaultMax }

  $defaultTimeout = 4000
  $parsed = 0
  if ([int]::TryParse([string]$env:ACS_PROPAGATION_TIMEOUT_MS, [ref]$parsed) -and $parsed -gt 0) {
    $defaultTimeout = [Math]::Min(15000, [Math]::Max(500, $parsed))
  }
  $effectiveTimeout = if ($TimeoutMs -gt 0) { [Math]::Min(15000, [Math]::Max(500, $TimeoutMs)) } else { $defaultTimeout }
  $status.timeoutMs = $effectiveTimeout

  # Advertise the regions the catalog can serve so the SPA settings panel can
  # build its region picker from live server data instead of a hard-coded list.
  $catalog = @(Get-DnsPropagationResolverCatalog)
  $status.catalogCount = $catalog.Count
  $regionCounts = [ordered]@{}
  foreach ($item in $catalog) {
    $key = ([string]$item.region).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($key)) { $key = 'global' }
    if (-not $regionCounts.Contains($key)) { $regionCounts[$key] = 0 }
    $regionCounts[$key]++
  }
  $status.availableRegions = @($regionCounts.Keys | ForEach-Object {
    [pscustomobject]@{ region = $_; resolverCount = $regionCounts[$_] }
  })

  $status.requestedCount = $effectiveMax

  # ---- Choose the resolvers to query ----
  #
  # A user-supplied list replaces the catalog entirely: "check these servers" is
  # an unambiguous instruction, and silently blending in 25 public resolvers would
  # make the verdict about something other than what was asked.
  $customList = @(ConvertFrom-DnsPropagationResolverInput -Text $CustomResolvers -MaxEntries 100)
  $selected = @()
  $outcomes = @{}

  if ($customList.Count -gt 0) {
    $status.usingCustom = $true
    $selected = @($customList | Select-Object -First $effectiveMax)
    $status.candidateCount = $selected.Count
    $outcomes = Invoke-DnsPropagationFanout -Resolvers $selected -Name $d -TypeCode $typeCode -TimeoutMs $effectiveTimeout
  }
  elseif ($ValidateResolvers) {
    # Over-select, query them ALL in one fan-out, then keep the first
    # $effectiveMax that returned a usable answer.
    #
    # The standalone tool validates candidates against `example.com` and then
    # re-queries the survivors. That costs two round trips AND still overstates
    # the yield, because a resolver can happily answer a tiny example.com A
    # record and then fail on the real question (a domain with 60+ TXT records
    # needs TCP fallback, which many open resolvers refuse). Validating with the
    # actual query removes both problems: one fan-out instead of two, and
    # "usable" means usable for THIS lookup. Because the fan-out is concurrent,
    # probing 3x the candidates costs the same wall time as probing N.
    $candidateTarget = [Math]::Min(300, [Math]::Max($effectiveMax * 3, $effectiveMax + 12))
    $candidates = @(Select-DnsPropagationResolvers -Regions $Regions -MaxResolvers $candidateTarget)
    $status.candidateCount = $candidates.Count

    if ($candidates.Count -gt 0) {
      $outcomes = Invoke-DnsPropagationFanout -Resolvers $candidates -Name $d -TypeCode $typeCode -TimeoutMs $effectiveTimeout
      $status.validated = $true

      # Candidates arrive in region round-robin order, so taking the usable ones
      # in sequence preserves the geographic spread.
      $usableSelection = [System.Collections.Generic.List[object]]::new()
      foreach ($candidate in $candidates) {
        if ($usableSelection.Count -ge $effectiveMax) { break }
        $outcome = $outcomes[([string]$candidate.ip).Trim()]
        if ($null -eq $outcome) { continue }
        if ($outcome.truncated) { continue }
        if ($outcome.rcode -eq 0 -or $outcome.rcode -eq 3) { $usableSelection.Add($candidate) }
      }

      if ($usableSelection.Count -eq 0) {
        # Nothing answered at all (typically outbound UDP/53 blocked). Fall back
        # to the plain balanced selection so the card can report the attempt
        # rather than claiming there are no resolvers.
        $status.validated = $false
        $selected = @($candidates | Select-Object -First $effectiveMax)
      } else {
        $selected = $usableSelection.ToArray()
      }
    }
  }
  else {
    $selected = @(Select-DnsPropagationResolvers -Regions $Regions -MaxResolvers $effectiveMax)
    $status.candidateCount = $selected.Count
    $outcomes = Invoke-DnsPropagationFanout -Resolvers $selected -Name $d -TypeCode $typeCode -TimeoutMs $effectiveTimeout
  }

  if ($selected.Count -eq 0) {
    $status.error = 'No public resolvers available for the selected regions.'
    $status.summary = 'NoResolvers'
    return $status
  }
  $status.resolverCount = $selected.Count
  $status.regions = @($selected | ForEach-Object { ([string]$_.region).ToLowerInvariant() } | Sort-Object -Unique)

  # Record health for every resolver we contacted, not just the ones we kept, so
  # the next request's selection can skip the failures outright.
  foreach ($probedIp in @($outcomes.Keys)) {
    Set-DnsPropagationHealthState -Ip $probedIp -Healthy ([bool]($null -ne $outcomes[$probedIp].rcode))
  }

  # ---- Build per-resolver rows ----
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($resolver in $selected) {
    $ip = ([string]$resolver.ip).Trim()
    $outcome = $outcomes[$ip]
    if ($null -eq $outcome) { $outcome = @{ answers = @(); rcode = $null; rcodeLabel = $null; transport = $null; responseMs = $null; error = 'No response.' } }

    $answers = @($outcome.answers)
    # "Responding" means the resolver gave us a usable view of the zone: NOERROR
    # (here is the record / here is nothing) or NXDOMAIN (the name does not
    # exist). A still-truncated answer is unreadable, and SERVFAIL / REFUSED is
    # the resolver failing rather than the domain, so neither is a vantage point
    # we can measure propagation from. Both are reported but kept out of the
    # verdict, the counts, and the map.
    $stillTruncated = [bool]$outcome.truncated
    $responded = (-not $stillTruncated) -and ($outcome.rcode -eq 0 -or $outcome.rcode -eq 3)

    $rows.Add([pscustomobject]@{
      ip          = $ip
      provider    = [string]$resolver.provider
      countryCode = [string]$resolver.countryCode
      city        = [string]$resolver.city
      # Kept nullable: a user-supplied resolver has no geolocation, and coercing
      # $null to 0.0 would drop a pin in the Atlantic off West Africa.
      latitude    = $(if ($null -eq $resolver.latitude) { $null } else { [double]$resolver.latitude })
      longitude   = $(if ($null -eq $resolver.longitude) { $null } else { [double]$resolver.longitude })
      region      = ([string]$resolver.region).ToLowerInvariant()
      anycast     = [bool]$resolver.anycast
      responded   = $responded
      truncated   = $stillTruncated
      rcode       = $outcome.rcode
      rcodeLabel  = $outcome.rcodeLabel
      transport   = $outcome.transport
      responseMs  = $outcome.responseMs
      answers     = $answers
      # Signature used for cross-resolver comparison. The parser already sorts
      # each set, so a plain join is a stable, order-independent fingerprint.
      signature   = ($answers -join "`n")
      error       = $outcome.error
      status      = 'unavailable'   # refined below
    })
  }

  $responders = @($rows | Where-Object { $_.responded -eq $true })
  $status.respondedCount = $responders.Count
  $status.truncatedCount = @($rows | Where-Object { $_.truncated -eq $true }).Count
  # Answered, but with a resolver-side failure rcode (SERVFAIL/REFUSED/...).
  $status.errorCount = @($rows | Where-Object { $_.responded -ne $true -and $_.truncated -ne $true -and $null -ne $_.rcode }).Count
  $status.unavailableCount = $rows.Count - $status.respondedCount - $status.truncatedCount - $status.errorCount

  if ($responders.Count -eq 0) {
    # Nothing answered: almost always outbound UDP/53 being blocked, not a
    # domain problem, so we report it as indeterminate rather than a failure.
    $status.results = $rows.ToArray()
    $status.state = 'unknown'
    $status.summary = 'NoResponders'
    $status.locations = @()
    return $status
  }

  $withAnswers = @($responders | Where-Object { $_.answers.Count -gt 0 })
  $status.answeredCount = $withAnswers.Count
  $status.emptyCount = $responders.Count - $withAnswers.Count

  # ---- Consensus = the most common NON-EMPTY answer set ----
  # Computing consensus over non-empty sets only is what makes the "some
  # resolvers have the record, some do not" case read correctly: the resolvers
  # still missing it are clearly 'norecord' instead of silently becoming the
  # majority and inverting the verdict.
  $signatureCounts = @{}
  foreach ($row in $withAnswers) {
    if (-not $signatureCounts.ContainsKey($row.signature)) { $signatureCounts[$row.signature] = 0 }
    $signatureCounts[$row.signature]++
  }
  $status.distinctAnswerSets = $signatureCounts.Keys.Count

  $consensusSignature = $null
  $consensusCount = 0
  foreach ($key in $signatureCounts.Keys) {
    if ($signatureCounts[$key] -gt $consensusCount) {
      $consensusCount = $signatureCounts[$key]
      $consensusSignature = $key
    }
  }
  if ($null -ne $consensusSignature) {
    $consensusRow = @($withAnswers | Where-Object { $_.signature -eq $consensusSignature })[0]
    $status.consensusAnswers = @($consensusRow.answers)
  }

  # ---- Classify each resolver ----
  $expected = ([string]$ExpectedValue).Trim()
  $useExpected = -not [string]::IsNullOrWhiteSpace($expected)
  foreach ($row in $rows) {
    if ($row.truncated -eq $true) { $row.status = 'truncated'; continue }
    if ($row.responded -ne $true) {
      $row.status = if ($null -ne $row.rcode) { 'error' } else { 'unavailable' }
      continue
    }
    if ($row.answers.Count -eq 0) {
      # NOERROR-with-no-answers and NXDOMAIN both mean "this resolver has no
      # such record" -- the signal that a change has not propagated here yet.
      $row.status = 'norecord'
      continue
    }
    if ($useExpected) {
      $matched = $false
      foreach ($answer in $row.answers) {
        if (([string]$answer).IndexOf($expected, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $matched = $true; break }
      }
      $row.status = if ($matched) { 'propagated' } else { 'mismatch' }
      continue
    }
    $row.status = if ($row.signature -eq $consensusSignature) { 'propagated' } else { 'mismatch' }
  }

  $status.matchingCount = @($rows | Where-Object { $_.status -eq 'propagated' }).Count
  $status.mismatchCount = @($rows | Where-Object { $_.status -eq 'mismatch' }).Count
  $noRecordCount = @($rows | Where-Object { $_.status -eq 'norecord' }).Count
  $status.propagationPercent = if ($responders.Count -gt 0) { [int][Math]::Round(100.0 * $status.matchingCount / $responders.Count) } else { 0 }

  # ---- Overall state ----
  #
  # Outlier tolerance for large samples: with 100 public resolvers in play, a
  # handful are ad-blocking, captive or deliberately lying resolvers that return
  # an empty answer for names they have never heard of. Letting a single such
  # server drive the whole card to FAIL would make big samples less trustworthy
  # than small ones. Below 20 responders every miss still counts, because there a
  # single divergent vantage point genuinely is signal.
  $partialThreshold = 1
  if ($responders.Count -ge 20) {
    $partialThreshold = [int][Math]::Ceiling($responders.Count * 0.05)
    if ($partialThreshold -lt 1) { $partialThreshold = 1 }
  }

  if ($status.matchingCount -eq 0 -and $status.mismatchCount -eq 0) {
    # Every responder agrees the record does not exist.
    $status.state = 'norecord'
    $status.summary = 'NoRecordAnywhere'
  } elseif ($noRecordCount -ge $partialThreshold -and $status.matchingCount -gt 0) {
    # The classic "still propagating" signature: present at some vantage points,
    # absent at others. This is the case that breaks ACS domain verification.
    $status.state = 'partial'
    $status.summary = 'PartiallyPropagated'
  } elseif ($status.mismatchCount -gt 0 -or $noRecordCount -gt 0) {
    # Everyone has *a* record, but not the same one (stale cache, split-horizon,
    # geo-DNS, or an edit that is still rolling out) -- or a below-threshold
    # number of resolvers reported no record at all.
    $status.state = 'mismatch'
    $status.summary = 'InconsistentAnswers'
  } else {
    $status.state = 'propagated'
    $status.summary = 'FullyPropagated'
  }

  $status.results = $rows.ToArray()

  # ---- Roll up to map markers ----
  # Several resolvers share a city (two in Seoul, two in Copenhagen, ...), so we
  # group by rounded coordinates and emit one marker per location. A location is
  # only green when every resolver there agrees.
  #
  # Only resolvers that actually returned a usable answer are rolled up: a pin
  # for a resolver that never replied says nothing about the domain and only
  # adds noise to the map. Non-responding resolvers remain in `results` for
  # callers that want the full picture.
  $locationMap = [ordered]@{}
  foreach ($row in ($rows | Where-Object { $_.responded -eq $true -and $null -ne $_.latitude -and $null -ne $_.longitude })) {
    $key = '{0:N2}|{1:N2}' -f $row.latitude, $row.longitude
    if (-not $locationMap.Contains($key)) {
      $locationMap[$key] = [pscustomobject]@{
        key         = $key
        name        = if ([string]::IsNullOrWhiteSpace($row.city)) { $row.countryCode } else { $row.city }
        countryCode = $row.countryCode
        latitude    = $row.latitude
        longitude   = $row.longitude
        anycast     = $row.anycast
        total       = 0
        propagated  = 0
        mismatch    = 0
        norecord    = 0
        providers   = @()
        status      = 'unknown'
      }
    }
    $entry = $locationMap[$key]
    $entry.total++
    $entry.providers = @($entry.providers + $row.provider)
    if (-not $row.anycast) { $entry.anycast = $false }
    switch ($row.status) {
      'propagated'  { $entry.propagated++ }
      'mismatch'    { $entry.mismatch++ }
      'norecord'    { $entry.norecord++ }
    }
  }
  foreach ($key in $locationMap.Keys) {
    $entry = $locationMap[$key]
    # Worst-first: one disagreeing or missing resolver colors the whole marker.
    $entry.status = if ($entry.mismatch -gt 0) { 'mismatch' }
      elseif ($entry.norecord -gt 0) { 'norecord' }
      else { 'propagated' }
  }
  $status.locations = @($locationMap.Values)

  return $status
}
