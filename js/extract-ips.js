const splitForwarded = /for\s*=\s*(?:"\[)?([0-9a-f\.:]+)/ig;
const splitXFF = /[0-9a-f\.:]+/ig;

export default function extractIPs(r) {
    const remoteAddr = r.remoteAddress;
    const rawForwarded = r.headersIn["Forwarded"];
    let ips = [];
    if (rawForwarded) {
        let match;
        while ((match = splitForwarded.exec(rawForwarded)) !== null) {
            if (isValidIP(match[1])) ips.push(match[1]);
        }
    } else {
        const rawXFF = r.headersIn["X-Forwarded-For"];
        if (rawXFF) {
            let match;
            while ((match = splitXFF.exec(rawXFF)) !== null) {
                if (isValidIP(match[0])) ips.push(match[0]);
            }
        }
    }
    ips.push(remoteAddr);
    return ips;
}

function isValidIPv4(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) {
        return false;
    }

    for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        if (!/^\d+$/.test(part)) {
            return false;
        }

        if (part.length > 1 && part.startsWith('0')) {
            return false;
        }

        const num = parseInt(part, 10);
        if (isNaN(num) || num < 0 || num > 255) {
            return false;
        }
    }

    return true;
}

function isValidIPv6(ip) {
    if (ip.includes('%')) {
        const zoneParts = ip.split('%');
        if (zoneParts.length !== 2) {
            return false;
        }

        if (zoneParts[1].length === 0) {
            return false;
        }

        ip = zoneParts[0];
    }

    let haveDoubleColons = false;
    if (ip.includes('::')) {
        if (ip.split('::').length > 2) return false;
        haveDoubleColons = true;
    }

    let containsIPv4 = false;
    if (ip.includes('.')) {
        const lastColonIndex = ip.lastIndexOf(':');
        if (lastColonIndex === -1) return false;

        const ipv4Part = ip.substring(lastColonIndex + 1);
        if (!isValidIPv4(ipv4Part)) {
            return false;
        }

        containsIPv4 = true;
        if (ip.charAt(lastColonIndex - 1) === ':') {
            ip = ip.substring(0, lastColonIndex - 1);
        } else {
            ip = ip.substring(0, lastColonIndex);
        }
    }

    let parts = [];
    const compressedParts = ip.split('::');
    for (let i = 0; i < compressedParts.length; i++) {
        const compressedPart = compressedParts[i];
        if (compressedPart.length === 0) continue;
        parts = parts.concat(compressedPart.split(':'));
    }
    const expectedMaxGroups = containsIPv4 ? 6 : 8;
    if (haveDoubleColons) {
        if (parts.length >= expectedMaxGroups) return false;
    } else {
        if (parts.length !== expectedMaxGroups) return false;
    }

    for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        if (!/^[0-9a-f]{1,4}$/i.test(part)) {
            return false;
        }
    }

    return true;
}

function isValidIP(ip) {
    if (typeof ip !== 'string' || ip.length === 0) {
        return false;
    }

    if (ip.includes(':')) {
        return isValidIPv6(ip);
    } else if (ip.includes('.')) {
        return isValidIPv4(ip);
    }

    return false;
}