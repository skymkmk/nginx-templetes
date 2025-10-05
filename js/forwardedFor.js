import extract_ips from "./extractIps.js";


export default function forwarded_for(r) {
    const ips = extract_ips(r);
    const forwarded_for = ips.map(v => {
        if (v.includes(":")) {
            return `for="[${v}]"`;
        } else {
            return `for=${v}`;
        }
    }).join(", ");
    return forwarded_for;
}