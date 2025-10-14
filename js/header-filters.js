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
    for (let i = 0; i < cookies.length; i++) {
        if (!cookies[i].toLowerCase().includes("samesite")) {
            cookies[i] = cookies[i].concat("; SameSite=Lax");
        }
        if (!cookies[i].toLowerCase().includes("secure")) {
            cookies[i] = cookies[i].concat("; Secure");
        }
    }
    r.headersOut['Set-Cookie'] = cookies;
}

export default { cookieFilter };