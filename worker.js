// IP Quality Check - Cloudflare Worker
// Replicates ip.sh functionality as a web service

const UA_Browser = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36';

// ─── IP Validation ──────────────────────────────────────────────────────────
function isValidIPv4(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every(p => {
    const n = Number(p);
    return Number.isInteger(n) && n >= 0 && n <= 255 && String(n) === p;
  });
}

function isValidIPv6(ip) {
  return /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:$|^:([0-9a-fA-F]{1,4}:){1,7}$|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})$|^:((:[0-9a-fA-F]{1,4}){1,7}|:)$/.test(ip);
}

function isValidIP(ip) {
  return isValidIPv4(ip) || isValidIPv6(ip);
}

function getIPVersion(ip) {
  return isValidIPv4(ip) ? 4 : 6;
}

// ─── DMS Coordinate Conversion ──────────────────────────────────────────────
function toDMS(lat, lon) {
  function convert(coord, dir) {
    const d = Math.floor(Math.abs(coord));
    const mFull = (Math.abs(coord) - d) * 60;
    const m = Math.floor(mFull);
    const s = Math.round((mFull - m) * 60);
    return `${d}°${m}′${s}″${dir}`;
  }
  const latDir = lat >= 0 ? 'N' : 'S';
  const lonDir = lon >= 0 ? 'E' : 'W';
  return `${convert(lon, lonDir)}, ${convert(lat, latDir)}`;
}

function generateMapUrl(lat, lon, radius) {
  let zoom = 15;
  if (radius > 1000) zoom = 12;
  else if (radius > 500) zoom = 13;
  else if (radius > 250) zoom = 14;
  return `https://www.google.com/maps?q=${lat},${lon}`;
}

// ─── API Fetchers ───────────────────────────────────────────────────────────
async function fetchJSON(url, options = {}) {
  try {
    const resp = await fetch(url, {
      headers: { 'User-Agent': UA_Browser, ...options.headers },
      ...options,
    });
    if (!resp.ok) return null;
    return await resp.json();
  } catch {
    return null;
  }
}

async function fetchText(url, options = {}) {
  try {
    const resp = await fetch(url, {
      headers: { 'User-Agent': UA_Browser, ...options.headers },
      ...options,
    });
    if (!resp.ok) return '';
    return await resp.text();
  } catch {
    return '';
  }
}

// ─── Database Fetchers (matching ip.sh) ─────────────────────────────────────

// Maxmind removed — no API key

async function db_ipinfo(ip) {
  const data = await fetchJSON(`https://ipinfo.io/widget/demo/${ip}`);
  if (!data) return null;
  const loc = data?.data?.loc?.split(',') || [];
  return {
    source: 'IPinfo',
    usetype: data?.data?.asn?.type || null,
    comtype: data?.data?.company?.type || null,
    countryCode: data?.data?.country || null,
    proxy: data?.data?.privacy?.proxy ?? null,
    tor: data?.data?.privacy?.tor ?? null,
    vpn: data?.data?.privacy?.vpn ?? null,
    server: data?.data?.privacy?.hosting ?? null,
    asn: data?.data?.asn?.asn?.replace(/^AS/, '') || null,
    org: data?.data?.asn?.name || null,
    city: data?.data?.city || null,
    post: data?.data?.postal || null,
    timezone: data?.data?.timezone || null,
    lat: loc[0] ? parseFloat(loc[0]) : null,
    lon: loc[1] ? parseFloat(loc[1]) : null,
    regCountryCode: data?.data?.abuse?.country || null,
  };
}

async function db_scamalytics(ip) {
  // Scrape scamalytics.com directly
  const html = await fetchText(`https://scamalytics.com/ip/${ip}`, {
    headers: {
      'User-Agent': UA_Browser,
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
    },
  });
  if (!html) return null;

  // Try to extract embedded JSON block first (most reliable)
  // The page contains a pre/code block with JSON like: {"score":"0","risk":"low","is_anonymous_vpn":false,...}
  const jsonMatch = html.match(/\{[^{}]*"score"\s*:\s*"?\d+"?[^{}]*"risk"\s*:\s*"[^"]*"[^{}]*\}/);
  if (jsonMatch) {
    try {
      const j = JSON.parse(jsonMatch[0]);
      const score = parseInt(j.score) || 0;
      let risk = 'Low';
      if (score >= 90) risk = 'Very High';
      else if (score >= 60) risk = 'High';
      else if (score >= 20) risk = 'Medium';

      // Combine public_proxy and web_proxy for proxy detection
      const proxy1 = j.is_public_proxy;
      const proxy2 = j.is_web_proxy;
      const proxy = (proxy1 === true || proxy2 === true) ? true :
        (proxy1 === false && proxy2 === false) ? false : null;

      return {
        source: 'Scamalytics',
        countryCode: null, // JSON block doesn't contain country
        proxy,
        tor: j.is_tor_exit_node ?? null,
        vpn: j.is_anonymous_vpn ?? null,
        server: j.is_server ?? null,
        abuser: j.is_blacklisted_external ?? null,
        robot: j.is_search_engine_robot ?? null,
        score,
        risk,
      };
    } catch { }
  }

  // Fallback: parse HTML directly
  const scoreMatch = html.match(/Fraud Score:\s*(\d+)/i);
  const score = scoreMatch ? parseInt(scoreMatch[1]) : null;
  if (score === null) return null;

  let risk = 'Low';
  if (score >= 90) risk = 'Very High';
  else if (score >= 60) risk = 'High';
  else if (score >= 20) risk = 'Medium';

  // Parse risk factors from HTML table (th label, followed by Yes/No value)
  const parseYesNo = (label) => {
    // Match: <th>Label</th> ... <td>Yes/No</td> or similar structures
    const re = new RegExp(label + '[\\s\\S]*?(?:Yes|No)', 'i');
    const m = html.match(re);
    if (!m) return null;
    return /Yes/i.test(m[0]);
  };

  const proxy1 = parseYesNo('Public Proxy');
  const proxy2 = parseYesNo('Web Proxy');
  const proxy = (proxy1 === true || proxy2 === true) ? true :
    (proxy1 === false && proxy2 === false) ? false : null;

  return {
    source: 'Scamalytics',
    countryCode: null,
    proxy,
    tor: parseYesNo('Tor Exit Node'),
    vpn: parseYesNo('Anonymizing VPN'),
    server: parseYesNo('Server'),
    abuser: null,
    robot: parseYesNo('Search Engine Robot'),
    score,
    risk,
  };
}

async function db_ipregistry(ip, env) {
  // First get API key from env, fallback to scraping ipregistry.co page
  let apiKey = env?.IPREGISTRY_API_KEY || '';
  if (!apiKey) {
    try {
      const html = await fetchText('https://ipregistry.co');
      const match = html.match(/apiKey="([a-zA-Z0-9_]+)"/);
      if (match) apiKey = match[1];
    } catch { }
  }
  if (!apiKey) return null;

  const data = await fetchJSON(`https://api.ipregistry.co/${ip}?hostname=true&key=${apiKey}`, {
    headers: {
      'authority': 'api.ipregistry.co',
      'origin': 'https://ipregistry.co',
      'referer': 'https://ipregistry.co/',
      'User-Agent': UA_Browser,
    },
  });
  if (!data) return null;
  const tor1 = data?.security?.is_tor;
  const tor2 = data?.security?.is_tor_exit;
  const tor = (tor1 === true || tor2 === true) ? true :
    (tor1 === false && tor2 === false) ? false : null;

  return {
    source: 'ipregistry',
    usetype: data?.connection?.type || null,
    comtype: data?.company?.type || null,
    countryCode: data?.location?.country?.code || null,
    proxy: data?.security?.is_proxy ?? null,
    tor,
    vpn: data?.security?.is_vpn ?? null,
    server: data?.security?.is_cloud_provider ?? null,
    abuser: data?.security?.is_abuser ?? null,
  };
}

async function db_ipapi(ip) {
  const data = await fetchJSON(`https://api.ipapi.is/?q=${ip}`);
  if (!data) return null;
  const scoreText = data?.company?.abuser_score || '';
  const scoreNum = parseFloat(scoreText) || 0;
  const riskText = scoreText.match(/\(([^)]+)\)/)?.[1] || '';
  const score = (scoreNum * 100).toFixed(2) + '%';

  let risk = 'Low';
  if (riskText === 'Very High') risk = 'Very High';
  else if (riskText === 'High') risk = 'High';
  else if (riskText === 'Elevated') risk = 'Elevated';
  else if (riskText === 'Low') risk = 'Low';
  else if (riskText === 'Very Low') risk = 'Very Low';

  return {
    source: 'ipapi',
    usetype: data?.asn?.type || null,
    comtype: data?.company?.type || null,
    countryCode: data?.location?.country_code || null,
    proxy: data?.is_proxy ?? null,
    tor: data?.is_tor ?? null,
    vpn: data?.is_vpn ?? null,
    server: data?.is_datacenter ?? null,
    abuser: data?.is_abuser ?? null,
    robot: data?.is_crawler ?? null,
    score,
    scoreNum,
    risk,
  };
}

async function db_abuseipdb(ip, env) {
  const ABUSEIPDB_KEY = env?.ABUSEIPDB_API_KEY || '';
  if (!ABUSEIPDB_KEY) return null;
  const data = await fetchJSON(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose=true`, {
    headers: {
      'Key': ABUSEIPDB_KEY,
      'Accept': 'application/json',
    },
  });
  if (!data?.data) return null;

  const usetype = data.data.usageType || '';
  const typeMap = {
    'Commercial': 'business',
    'Data Center/Web Hosting/Transit': 'hosting',
    'University/College/School': 'education',
    'Government': 'government',
    'Organization': 'organization',
    'Military': 'military',
    'Library': 'library',
    'Content Delivery Network': 'cdn',
    'Fixed Line ISP': 'isp',
    'Mobile ISP': 'mobile',
    'Search Engine Spider': 'spider',
    'Reserved': 'reserved',
  };

  const score = parseInt(data.data.abuseConfidenceScore) || 0;
  let risk = 'Low';
  if (score >= 75) risk = 'DoS-level';
  else if (score >= 25) risk = 'High';

  return {
    source: 'AbuseIPDB',
    usetype: typeMap[usetype] || usetype || null,
    countryCode: data.data.countryCode || null,
    tor: data.data.isTor ?? null,
    score,
    risk,
  };
}

// IP2Location removed — no API key yet

async function db_dbip(ip) {
  const html = await fetchText(`https://db-ip.com/${ip}`);
  if (!html) return null;

  // Parse threat level
  const threatMatch = html.match(/Estimated threat level for this IP address is\s*<span[^>]*>([^<]*)<\/span>/i);
  const riskText = threatMatch ? threatMatch[1].trim().toLowerCase() : '';
  let risk = null, score = null;
  if (riskText === 'low') { risk = 'Low'; score = 0; }
  else if (riskText === 'medium') { risk = 'Medium'; score = 50; }
  else if (riskText === 'high') { risk = 'High'; score = 100; }

  // Parse crawler/proxy/abuser from HTML
  const crawlerSection = html.match(/Crawler[\s\S]*?(<span class="sr-only">)(Yes|No)/i);
  const robot = crawlerSection ? crawlerSection[2].toLowerCase() === 'yes' : null;

  // Parse country code from JSON block
  const ccMatch = html.match(/"countryCode"\s*:\s*"([^"]*)"/);
  const countryCode = ccMatch ? ccMatch[1] : null;

  return {
    source: 'DB-IP',
    countryCode,
    robot,
    risk,
    score,
  };
}

// IPQS removed — gateway timeout, no API key yet

async function db_ipdata(ip, env) {
  const IPDATA_KEY = env?.IPDATA_API_KEY || '';
  if (!IPDATA_KEY) return null;
  const data = await fetchJSON(`https://api.ipdata.co/${ip}?api-key=${IPDATA_KEY}`);
  if (!data) return null;

  const abuser1 = data?.threat?.is_threat;
  const abuser2 = data?.threat?.is_known_abuser;
  const abuser3 = data?.threat?.is_known_attacker;
  const abuser = (abuser1 === true || abuser2 === true || abuser3 === true) ? true :
    (abuser1 === false && abuser2 === false && abuser3 === false) ? false : null;

  return {
    source: 'ipdata',
    countryCode: data?.country_code || null,
    proxy: data?.threat?.is_proxy ?? null,
    tor: data?.threat?.is_tor ?? null,
    server: data?.threat?.is_datacenter ?? null,
    abuser,
  };
}

// ─── Main Check Handler ─────────────────────────────────────────────────────
async function handleCheck(ip, env) {
  const [ipinfo, scamalytics, ipregistry, ipapi, abuseipdb, dbip, ipdata] =
    await Promise.all([
      db_ipinfo(ip),
      db_scamalytics(ip),
      db_ipregistry(ip, env),
      db_ipapi(ip),
      db_abuseipdb(ip, env),
      db_dbip(ip),
      db_ipdata(ip, env),
    ]);

  const basicSource = ipinfo;
  const isNative = basicSource?.countryCode === (basicSource?.regCountryCode || basicSource?.countryCode);

  return {
    ip,
    ipVersion: getIPVersion(ip),
    basic: {
      source: 'IPinfo',
      asn: basicSource?.asn,
      org: basicSource?.org,
      city: basicSource?.city,
      post: basicSource?.post,
      subdivision: basicSource?.subdivision,
      lat: basicSource?.lat,
      lon: basicSource?.lon,
      dms: basicSource?.lat && basicSource?.lon ? toDMS(basicSource.lat, basicSource.lon) : null,
      map: basicSource?.lat && basicSource?.lon ? generateMapUrl(basicSource.lat, basicSource.lon, 1000) : null,
      countryCode: basicSource?.countryCode,
      country: basicSource?.country || basicSource?.countryCode,
      regCountryCode: basicSource?.regCountryCode,
      timezone: basicSource?.timezone,
      isNative,
    },
    type: {
      ipinfo: { usetype: ipinfo?.usetype, comtype: ipinfo?.comtype },
      ipregistry: { usetype: ipregistry?.usetype, comtype: ipregistry?.comtype },
      ipapi: { usetype: ipapi?.usetype, comtype: ipapi?.comtype },
      abuseipdb: { usetype: abuseipdb?.usetype },
    },
    scores: {
      scamalytics: scamalytics ? { score: scamalytics.score, risk: scamalytics.risk, max: 100 } : null,
      ipapi: ipapi ? { score: ipapi.score, scoreNum: ipapi.scoreNum, risk: ipapi.risk, max: 1 } : null,
      abuseipdb: abuseipdb ? { score: abuseipdb.score, risk: abuseipdb.risk, max: 100 } : null,
      dbip: dbip ? { score: dbip.score, risk: dbip.risk, max: 100 } : null,
    },
    factors: {
      databases: ['ipapi', 'ipregistry', 'Scamalytics', 'ipdata', 'IPinfo', 'AbuseIPDB', 'DB-IP'],
      countryCode: [ipapi?.countryCode, ipregistry?.countryCode, scamalytics?.countryCode, ipdata?.countryCode, ipinfo?.countryCode, abuseipdb?.countryCode, dbip?.countryCode],
      proxy: [ipapi?.proxy, ipregistry?.proxy, scamalytics?.proxy, ipdata?.proxy, ipinfo?.proxy, null, null],
      tor: [ipapi?.tor, ipregistry?.tor, scamalytics?.tor, ipdata?.tor, ipinfo?.tor, abuseipdb?.tor, null],
      vpn: [ipapi?.vpn, ipregistry?.vpn, scamalytics?.vpn, null, ipinfo?.vpn, null, null],
      server: [ipapi?.server, ipregistry?.server, scamalytics?.server, ipdata?.server, ipinfo?.server, null, null],
      abuser: [ipapi?.abuser, ipregistry?.abuser, scamalytics?.abuser, ipdata?.abuser, null, null, null],
      robot: [ipapi?.robot, null, scamalytics?.robot, null, null, null, dbip?.robot],
    },
  };
}

// ─── HTML Frontend ──────────────────────────────────────────────────────────

function getHTML(visitorIP) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IP 质量体检 | IP Quality Check</title>
<meta name="description" content="在线查询IP地址质量，包括基础信息、风险评分、IP类型和风险因子检测。基于多个权威数据库聚合分析。">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg-primary:#0a0e1a;--bg-secondary:#111827;--bg-card:#1a1f35;--bg-card-hover:#1e2440;
  --border:#2a3050;--border-glow:rgba(99,102,241,0.3);
  --text-primary:#f1f5f9;--text-secondary:#94a3b8;--text-muted:#64748b;
  --accent:#6366f1;--accent-light:#818cf8;--accent-glow:rgba(99,102,241,0.15);
  --green:#22c55e;--green-bg:rgba(34,197,94,0.12);--green-border:rgba(34,197,94,0.3);
  --yellow:#eab308;--yellow-bg:rgba(234,179,8,0.12);--yellow-border:rgba(234,179,8,0.3);
  --red:#ef4444;--red-bg:rgba(239,68,68,0.12);--red-border:rgba(239,68,68,0.3);
  --orange:#f97316;--orange-bg:rgba(249,115,22,0.12);
  --cyan:#06b6d4;--cyan-bg:rgba(6,182,212,0.1);
}
html{font-family:'Inter',system-ui,-apple-system,sans-serif;background:var(--bg-primary);color:var(--text-primary);scroll-behavior:smooth}
body{min-height:100vh;background:var(--bg-primary);overflow-x:hidden}
body::before{content:'';position:fixed;top:0;left:0;width:100%;height:100%;background:radial-gradient(ellipse at 20% 0%, rgba(99,102,241,0.08) 0%, transparent 50%),radial-gradient(ellipse at 80% 100%, rgba(6,182,212,0.06) 0%, transparent 50%);pointer-events:none;z-index:0}

.container{max-width:960px;margin:0 auto;padding:2rem 1.5rem;position:relative;z-index:1}
.header{text-align:center;padding:3rem 0 2rem}
.header h1{font-size:2.2rem;font-weight:800;background:linear-gradient(135deg,#818cf8,#06b6d4);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;letter-spacing:-0.02em}
.header p{color:var(--text-secondary);margin-top:0.5rem;font-size:0.95rem;font-weight:300}
.header .version{font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:var(--text-muted);margin-top:0.3rem}

.search-box{max-width:600px;margin:1.5rem auto 3rem;position:relative}
.search-box form{display:flex;gap:0;border-radius:16px;overflow:hidden;border:1px solid var(--border);background:var(--bg-card);transition:border-color 0.3s,box-shadow 0.3s}
.search-box form:focus-within{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow),0 8px 32px rgba(0,0,0,0.3)}
.search-box input{flex:1;padding:1rem 1.5rem;background:transparent;border:none;color:var(--text-primary);font-size:1.05rem;outline:none;font-family:'JetBrains Mono',monospace;font-weight:400}
.search-box input::placeholder{color:var(--text-muted);font-family:'Inter',sans-serif;font-weight:300}
.search-box button{padding:1rem 2rem;background:linear-gradient(135deg,var(--accent),#4f46e5);border:none;color:white;font-weight:600;cursor:pointer;font-size:0.95rem;transition:all 0.2s;letter-spacing:0.01em}
.search-box button:hover{background:linear-gradient(135deg,var(--accent-light),var(--accent));transform:scale(1.02)}
.search-box button:active{transform:scale(0.98)}
.search-box button:disabled{opacity:0.5;cursor:not-allowed;transform:none}
.visitor-ip{text-align:center;margin-top:0.8rem;font-size:0.82rem;color:var(--text-muted)}
.visitor-ip span{color:var(--accent-light);cursor:pointer;border-bottom:1px dashed var(--accent-light);transition:color 0.2s}
.visitor-ip span:hover{color:var(--cyan)}

.card{background:var(--bg-card);border:1px solid var(--border);border-radius:16px;padding:1.8rem;margin-bottom:1.5rem;transition:border-color 0.3s,box-shadow 0.3s;position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(99,102,241,0.3),transparent);opacity:0;transition:opacity 0.3s}
.card:hover{border-color:rgba(99,102,241,0.2)}.card:hover::before{opacity:1}
.card-title{display:flex;align-items:center;gap:0.7rem;font-size:1.05rem;font-weight:700;margin-bottom:1.4rem;color:var(--text-primary)}
.card-title .num{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:8px;background:linear-gradient(135deg,var(--accent),#4f46e5);color:white;font-size:0.8rem;font-weight:700;flex-shrink:0}
.card-title .icon{font-size:1.1rem}

.info-grid{display:grid;gap:0.6rem}
.info-row{display:flex;align-items:baseline;gap:0.5rem;padding:0.5rem 0.7rem;border-radius:8px;transition:background 0.2s}
.info-row:hover{background:rgba(99,102,241,0.04)}
.info-label{color:var(--text-secondary);font-size:0.85rem;min-width:110px;font-weight:400;flex-shrink:0}
.info-value{color:var(--text-primary);font-size:0.9rem;font-weight:500;font-family:'JetBrains Mono',monospace;word-break:break-all}
.info-value a{color:var(--cyan);text-decoration:none;border-bottom:1px dashed var(--cyan);transition:color 0.2s}
.info-value a:hover{color:var(--accent-light)}

.tag{display:inline-block;padding:0.2rem 0.7rem;border-radius:6px;font-size:0.78rem;font-weight:600;letter-spacing:0.02em}
.tag-green{background:var(--green-bg);color:var(--green);border:1px solid var(--green-border)}
.tag-red{background:var(--red-bg);color:var(--red);border:1px solid var(--red-border)}
.tag-yellow{background:var(--yellow-bg);color:var(--yellow);border:1px solid var(--yellow-border)}
.tag-blue{background:var(--cyan-bg);color:var(--cyan);border:1px solid rgba(6,182,212,0.3)}
.tag-muted{background:rgba(100,116,139,0.1);color:var(--text-muted);border:1px solid rgba(100,116,139,0.2)}

.type-table{width:100%;border-collapse:separate;border-spacing:0;overflow:hidden;border-radius:10px;border:1px solid var(--border)}
.type-table th,.type-table td{padding:0.6rem 0.5rem;text-align:center;font-size:0.78rem;border-bottom:1px solid var(--border)}
.type-table th{background:rgba(99,102,241,0.06);color:var(--text-secondary);font-weight:500;font-size:0.72rem;text-transform:uppercase;letter-spacing:0.05em}
.type-table tr:last-child td{border-bottom:none}
.type-table td{color:var(--text-primary);font-weight:500}

.score-item{display:flex;align-items:center;gap:0.8rem;padding:0.7rem 0}
.score-item+.score-item{border-top:1px solid rgba(42,48,80,0.5)}
.score-name{min-width:100px;font-size:0.82rem;color:var(--text-secondary);font-weight:500}
.score-bar-container{flex:1;height:8px;background:rgba(255,255,255,0.05);border-radius:4px;overflow:hidden;position:relative}
.score-bar{height:100%;border-radius:4px;transition:width 1s cubic-bezier(0.22,1,0.36,1);position:relative}
.score-bar::after{content:'';position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,0.15));border-radius:4px}
.score-value{min-width:50px;text-align:right;font-family:'JetBrains Mono',monospace;font-size:0.82rem;font-weight:600}
.score-risk{min-width:70px;text-align:right}

.factor-grid{display:grid;grid-template-columns:90px repeat(var(--cols,8),1fr);gap:0;font-size:0.75rem;border:1px solid var(--border);border-radius:10px;overflow:hidden}
.factor-grid .fh{background:rgba(99,102,241,0.06);padding:0.55rem 0.3rem;text-align:center;font-weight:500;color:var(--text-secondary);border-bottom:1px solid var(--border);font-size:0.68rem;text-transform:uppercase;letter-spacing:0.03em}
.factor-grid .fl{padding:0.5rem 0.6rem;display:flex;align-items:center;color:var(--text-secondary);font-weight:500;border-bottom:1px solid rgba(42,48,80,0.3);font-size:0.78rem}
.factor-grid .fc{padding:0.5rem 0.3rem;display:flex;align-items:center;justify-content:center;border-bottom:1px solid rgba(42,48,80,0.3)}
.factor-grid .fc:nth-child(even){background:rgba(255,255,255,0.01)}
.factor-yes{color:var(--red);font-weight:700;font-size:0.8rem}
.factor-no{color:var(--green);font-weight:600;font-size:0.8rem}
.factor-na{color:var(--text-muted);font-size:0.72rem}
.factor-cc{color:var(--cyan);font-family:'JetBrains Mono',monospace;font-size:0.75rem;font-weight:600}

.loading-overlay{display:none;position:fixed;inset:0;background:rgba(10,14,26,0.85);z-index:100;backdrop-filter:blur(8px);justify-content:center;align-items:center;flex-direction:column;gap:1.5rem}
.loading-overlay.active{display:flex}
.spinner{width:48px;height:48px;border:3px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin 0.8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.loading-text{color:var(--text-secondary);font-size:0.95rem;font-weight:400;animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:0.5}50%{opacity:1}}

.error-msg{background:var(--red-bg);border:1px solid var(--red-border);border-radius:12px;padding:1rem 1.5rem;color:var(--red);text-align:center;margin-bottom:1.5rem;font-weight:500;display:none}
.result-area{display:none}
.result-area.active{display:block;animation:fadeUp 0.5s ease}
@keyframes fadeUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}

.footer{text-align:center;padding:2rem 0;color:var(--text-muted);font-size:0.78rem}
.footer a{color:var(--accent-light);text-decoration:none}

@media(max-width:768px){
  .container{padding:1rem}
  .header h1{font-size:1.6rem}
  .card{padding:1.2rem}
  .factor-grid{font-size:0.65rem;grid-template-columns:70px repeat(var(--cols,8),1fr)}
  .factor-grid .fl{font-size:0.68rem;padding:0.4rem}
  .factor-grid .fh{font-size:0.6rem;padding:0.4rem 0.2rem}
  .info-label{min-width:85px;font-size:0.8rem}
  .score-name{min-width:75px;font-size:0.76rem}
}
</style>
</head>
<body>

<div class="container">
  <header class="header">
    <h1>🔍 IP 质量体检</h1>
    <p>多数据库聚合分析 · IP Quality Check</p>
    <div class="version">Powered by Cloudflare Workers</div>
  </header>

  <div class="search-box">
    <form id="searchForm" onsubmit="return doSearch(event)">
      <input type="text" id="ipInput" placeholder="输入 IP 地址查询..." autocomplete="off" spellcheck="false">
      <button type="submit" id="searchBtn">查 询</button>
    </form>
    <div class="visitor-ip">当前访问IP：<span id="visitorIP" onclick="fillVisitorIP()">${visitorIP || '检测中...'}</span></div>
  </div>

  <div class="error-msg" id="errorMsg"></div>

  <div class="result-area" id="resultArea">
    <!-- 1. Basic Info -->
    <div class="card" id="cardBasic">
      <div class="card-title"><span class="num">1</span><span class="icon">📋</span> 基础信息</div>
      <div class="info-grid" id="basicInfo"></div>
    </div>

    <!-- 2. IP Type -->
    <div class="card" id="cardType">
      <div class="card-title"><span class="num">2</span><span class="icon">🏷️</span> IP 类型属性</div>
      <div id="typeInfo"></div>
    </div>

    <!-- 3. Risk Scores -->
    <div class="card" id="cardScore">
      <div class="card-title"><span class="num">3</span><span class="icon">📊</span> 风险评分</div>
      <div id="scoreInfo"></div>
    </div>

    <!-- 4. Risk Factors -->
    <div class="card" id="cardFactor">
      <div class="card-title"><span class="num">4</span><span class="icon">🛡️</span> 风险因子</div>
      <div id="factorInfo"></div>
    </div>
  </div>

  <footer class="footer">
    基于 <a href="https://github.com/xykt/IPQuality" target="_blank">IPQuality (ip.sh)</a> · Cloudflare Workers 版
  </footer>
</div>

<div class="loading-overlay" id="loading">
  <div class="spinner"></div>
  <div class="loading-text">正在查询多个数据库，请稍候...</div>
</div>

<script>
const visitorIP = '${visitorIP || ''}';

function fillVisitorIP() {
  document.getElementById('ipInput').value = visitorIP;
  document.getElementById('ipInput').focus();
}

function doSearch(e) {
  e.preventDefault();
  const ip = document.getElementById('ipInput').value.trim();
  if (!ip) { showError('请输入 IP 地址'); return false; }
  checkIP(ip);
  return false;
}

function showError(msg) {
  const el = document.getElementById('errorMsg');
  el.textContent = msg;
  el.style.display = 'block';
  setTimeout(() => el.style.display = 'none', 5000);
}

async function checkIP(ip) {
  const loading = document.getElementById('loading');
  const resultArea = document.getElementById('resultArea');
  const btn = document.getElementById('searchBtn');

  document.getElementById('errorMsg').style.display = 'none';
  resultArea.classList.remove('active');
  loading.classList.add('active');
  btn.disabled = true;

  try {
    const resp = await fetch('/api/check?ip=' + encodeURIComponent(ip));
    const data = await resp.json();
    if (data.error) {
      showError(data.error);
      return;
    }
    renderResult(data);
    resultArea.classList.add('active');
  } catch(e) {
    showError('查询失败，请稍后重试: ' + e.message);
  } finally {
    loading.classList.remove('active');
    btn.disabled = false;
  }
}

function esc(s) { const d=document.createElement('div');d.textContent=s||'';return d.innerHTML; }

function renderResult(d) {
  renderBasic(d.basic, d.ip);
  renderType(d.type);
  renderScores(d.scores);
  renderFactors(d.factors);
}

function renderBasic(b, ip) {
  const el = document.getElementById('basicInfo');
  let html = '';
  const row = (label, val) => val && val !== 'null' ? '<div class="info-row"><span class="info-label">' + label + '</span><span class="info-value">' + val + '</span></div>' : '';

  html += '<div class="info-row"><span class="info-label">数据源</span><span class="info-value"><span class="tag tag-blue">' + esc(b.source) + '</span></span></div>';
  html += row('IP 地址', esc(ip));
  if (b.asn) html += row('自治系统号', 'AS' + esc(b.asn));
  if (b.org) html += row('组织', esc(b.org));
  if (b.dms) html += row('坐标', esc(b.dms));
  if (b.map) html += '<div class="info-row"><span class="info-label">地图</span><span class="info-value"><a href="' + esc(b.map) + '" target="_blank">' + esc(b.map) + '</a></span></div>';

  let cityParts = [b.subdivision, b.city, b.post].filter(x => x && x !== 'null');
  if (cityParts.length) html += row('城市', esc(cityParts.join(', ')));

  let countryStr = '';
  if (b.countryCode && b.countryCode !== 'null') countryStr = '[' + b.countryCode + '] ' + (b.country || '');
  if (b.continentCode && b.continentCode !== 'null') countryStr += ', [' + b.continentCode + '] ' + (b.continent || '');
  if (countryStr) html += row('使用地', esc(countryStr));

  if (b.regCountryCode && b.regCountryCode !== 'null') html += row('注册地', esc('[' + b.regCountryCode + '] ' + (b.regCountry || '')));
  if (b.timezone && b.timezone !== 'null') html += row('时区', esc(b.timezone));

  if (b.countryCode && b.countryCode !== 'null') {
    const native = b.isNative;
    html += '<div class="info-row"><span class="info-label">IP 类型</span><span class="info-value"><span class="tag ' + (native ? 'tag-green' : 'tag-red') + '">' + (native ? '原生IP' : '广播IP') + '</span></span></div>';
  }
  el.innerHTML = html;
}

function normalizeType(t) {
  if (!t) return '-';
  const map = {business:'商业',isp:'家宽',hosting:'机房',education:'教育',government:'政府',banking:'银行',organization:'组织',military:'军队',library:'图书馆',cdn:'CDN',mobile:'手机',spider:'蜘蛛',reserved:'保留'};
  const tl = t.toLowerCase();
  return map[tl] || t;
}
function typeTag(t) {
  if (!t || t === '-') return '<span class="tag tag-muted">N/A</span>';
  const tl = (typeof t === 'string' ? t : '').toLowerCase();
  let cls = 'tag-yellow';
  if (tl === 'isp' || tl === 'mobile' || tl === '家宽' || tl === '手机') cls = 'tag-green';
  else if (tl === 'hosting' || tl === 'cdn' || tl === 'spider' || tl === '机房') cls = 'tag-red';
  return '<span class="tag ' + cls + '">' + esc(normalizeType(t)) + '</span>';
}

function renderType(t) {
  const dbs = ['IPinfo', 'ipregistry', 'ipapi', 'AbuseIPDB'];
  const keys = ['ipinfo', 'ipregistry', 'ipapi', 'abuseipdb'];
  let html = '<table class="type-table"><thead><tr><th>数据库</th>';
  dbs.forEach(d => html += '<th>' + d + '</th>');
  html += '</tr></thead><tbody>';
  html += '<tr><td style="color:var(--text-secondary);font-weight:500">使用类型</td>';
  keys.forEach(k => html += '<td>' + typeTag(t[k]?.usetype) + '</td>');
  html += '</tr><tr><td style="color:var(--text-secondary);font-weight:500">公司类型</td>';
  keys.forEach(k => html += '<td>' + typeTag(t[k]?.comtype) + '</td>');
  html += '</tr></tbody></table>';
  document.getElementById('typeInfo').innerHTML = html;
}

function getScoreColor(score, max) {
  const pct = max > 0 ? score / max : 0;
  if (pct < 0.25) return 'var(--green)';
  if (pct < 0.6) return 'var(--yellow)';
  if (pct < 0.8) return 'var(--orange)';
  return 'var(--red)';
}
function getRiskTag(risk) {
  if (!risk) return '';
  const r = risk.toLowerCase();
  let cls = 'tag-green';
  if (r.includes('high') || r.includes('dos') || r.includes('risky')) cls = 'tag-red';
  else if (r.includes('medium') || r.includes('elevated') || r.includes('suspicious')) cls = 'tag-yellow';
  else if (r.includes('very low')) cls = 'tag-green';
  const map = {'low':'低风险','very low':'极低风险','medium':'中风险','elevated':'较高','high':'高风险','very high':'极高风险','dos-level':'建议封禁','suspicious':'可疑','risky':'存在风险','high risk':'高风险'};
  return '<span class="tag ' + cls + '">' + (map[r] || risk) + '</span>';
}

function renderScores(s) {
  const el = document.getElementById('scoreInfo');
  let html = '';
  const items = [
    { name: 'Scamalytics', d: s.scamalytics, max: 100 },
    { name: 'ipapi', d: s.ipapi, max: 100 },
    { name: 'AbuseIPDB', d: s.abuseipdb, max: 100 },
    { name: 'DB-IP', d: s.dbip, max: 100 },
  ];
  items.forEach(item => {
    if (!item.d || item.d.score === null || item.d.score === undefined) return;
    const score = item.name === 'ipapi' ? (item.d.scoreNum * 100) : item.d.score;
    const pct = Math.min(100, Math.max(0, (score / item.max) * 100));
    const color = getScoreColor(score, item.max);
    const dispScore = item.name === 'ipapi' ? item.d.score : item.d.score;
    html += '<div class="score-item"><span class="score-name">' + item.name + '</span>';
    html += '<div class="score-bar-container"><div class="score-bar" style="width:' + pct + '%;background:' + color + '"></div></div>';
    html += '<span class="score-value" style="color:' + color + '">' + dispScore + '</span>';
    html += '<span class="score-risk">' + getRiskTag(item.d.risk) + '</span></div>';
  });
  if (!html) html = '<div style="color:var(--text-muted);text-align:center;padding:1rem">暂无数据</div>';
  el.innerHTML = html;
}

function factorCell(val) {
  if (val === true) return '<span class="factor-yes">✗ 是</span>';
  if (val === false) return '<span class="factor-no">✓ 否</span>';
  if (typeof val === 'string' && val.length === 2) return '<span class="factor-cc">' + esc(val) + '</span>';
  return '<span class="factor-na">N/A</span>';
}

function renderFactors(f) {
  const el = document.getElementById('factorInfo');
  const cols = f.databases.length;
  let html = '<div class="factor-grid" style="--cols:' + cols + '">';
  html += '<div class="fh"></div>';
  f.databases.forEach(d => html += '<div class="fh">' + d + '</div>');

  const labels = [['地区','countryCode'],['代理','proxy'],['Tor','tor'],['VPN','vpn'],['服务器','server'],['滥用','abuser'],['机器人','robot']];
  labels.forEach(([label, key]) => {
    html += '<div class="fl">' + label + '</div>';
    f[key].forEach(v => html += '<div class="fc">' + factorCell(v) + '</div>');
  });
  html += '</div>';
  el.innerHTML = html;
}
</script>
</body>
</html>`;
}

// ─── Worker Entry Point ─────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // API endpoint
    if (url.pathname === '/api/check') {
      const ip = url.searchParams.get('ip');
      if (!ip || !isValidIP(ip)) {
        return new Response(JSON.stringify({ error: 'IP 地址格式错误' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }

      try {
        const result = await handleCheck(ip, env);
        return new Response(JSON.stringify(result), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: '查询失败: ' + e.message }), {
          status: 500,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }
    }

    // Serve HTML frontend
    const visitorIP = request.headers.get('CF-Connecting-IP') || '';
    return new Response(getHTML(visitorIP), {
      headers: { 'Content-Type': 'text/html;charset=UTF-8' },
    });
  },
};
