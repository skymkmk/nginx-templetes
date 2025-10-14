import extractIPs from "./extract-ips.js";

export default function xff(r) {
    const ips = extractIPs(r);
    const xff = ips.join(",");
    return xff;
}