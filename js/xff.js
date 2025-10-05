import extract_ips from "./extractIps.js";

export default function xff(r) {
    const ips = extract_ips(r);
    const xff = ips.join(",");
    return xff;
}