import extractIPs from "./extract-ips.js";


export default function forwardedFor(r) {
    const ips = extractIPs(r);
    const forwardedFor = ips.map(v => {
        if (v.includes(":")) {
            return `for="[${v}]"`;
        } else {
            return `for=${v}`;
        }
    }).join(", ");
    return forwardedFor;
}