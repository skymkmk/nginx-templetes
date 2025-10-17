/// <reference types="njs-types/ngx_http_js_module.d.ts" />

/**
 * @param {NginxHTTPRequest} r 
 * @description
 * 为反向代理的后端强制添加 `Secure` 和在未添加 `SameSite` 时强制添加 `SameSite=Lax`
 * 
 * 值得注意的是如果目标浏览器是 20 年以前的浏览器，则强制添加 `SameSite=Lax` 会破坏追踪器的功能
 */
function cookieFilter(r) {
    let cookies = r.headersOut['Set-Cookie'];
    if (!cookies) return;
    r.headersOut['Set-Cookie'] = cookies.map(v => {
        if (!v.toLowerCase().includes("samesite") || !v.toLowerCase().includes("secure")) {
            let modifiedCookie = v.split(';').map(v => v.trim()).filter(Boolean);
            if (!modifiedCookie.some(v => v.toLowerCase().startsWith("samesite"))) modifiedCookie.push("SameSite=Lax");
            if (!modifiedCookie.some(v => v.toLowerCase().startsWith("secure"))) modifiedCookie.push("Secure");
            return modifiedCookie.join("; ");
        }
        return v;
    });
}

/**
 * 
 * @param {NginxHTTPRequest} r 
 */
function varyFilter(r) {
    const vary = r.headersOut["Vary"];
    /** @type {string | undefined} */
    let modifiedVary;
    if (vary) {
        if (vary.toLowerCase().includes("accept-encoding")) return;
        if (vary.includes("*")) return;
        modifiedVary = vary.split(',').map(v => v.trim()).concat("Accept-Encoding").join(", ");
    } else modifiedVary = "Accept-Encoding";
    r.headersOut["Vary"] = modifiedVary;
}

/**
 * 
 * @param {NginxHTTPRequest} r 
 */
function cspFilter(r) {
    let upstreamCSP = r.headersOut["Content-Security-Policy"];
    if (upstreamCSP && Array.isArray(upstreamCSP)) {
        upstreamCSP = upstreamCSP[0];
    }
    if (upstreamCSP) {
        let csps = upstreamCSP.split(';').map(v => v.trim()).filter(Boolean).filter(v => !/^(?:frame-ancestors|form-action)/i.test(v));
        csps.push("frame-ancestors 'self'");
        csps.push("form-action 'self'");
        if (!csps.some(v => v.toLowerCase().startsWith("object-src"))) csps.push("object-src 'none'");
        if (!csps.some(v => v.toLowerCase().startsWith("base-uri"))) csps.push("base-uri 'self'");
        if (!csps.some(v => v.toLowerCase().startsWith("upgrade-insecure-requests"))) csps.push("upgrade-insecure-requests");
        let finalCSPs = csps.join("; ");
        r.headersOut["Content-Security-Policy"] = finalCSPs;
    } else {
        r.headersOut["Content-Security-Policy"] = "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'; upgrade-insecure-requests";
    }
}

/**
 * 
 * @param {NginxHTTPRequest} r 
 */
function commonHeaderFilter(r) {
    // const serverPort = r.variables.server_port;
    r.headersOut["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains";
    // r.headersOut["Alt-Svc"] = `h3=":${serverPort}"; ma=63072000; persist=1`;
    if (!r.headersOut["X-Content-Type-Options"]) r.headersOut["X-Content-Type-Options"] = "nosniff";
    if (!r.headersOut["Cross-Origin-Resource-Policy"]) r.headersOut["Cross-Origin-Resource-Policy"] = "same-site";
    if (!r.headersOut["Referrer-Policy"]) r.headersOut["Referrer-Policy"] = "strict-origin-when-cross-origin";
}

/**
 * 
 * @param {NginxHTTPRequest} r 
 */
function universalFilter(r) {
    commonHeaderFilter(r);
    varyFilter(r);
    cookieFilter(r);
    cspFilter(r);
}

export default { universalFilter };