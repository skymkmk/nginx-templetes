const split_forwarded = /for\s*=\s*(?:"\[)?([0-9a-f\.:]+)/ig;
const split_xff = /[0-9a-f\.:]+/ig;

export default function extract_ips(r) {
    const remote_addr = r.remoteAddress;
    const raw_forwarded = r.headersIn["Forwarded"];
    let ips = [];
    if (raw_forwarded) {
        let match;
        while ((match = split_forwarded.exec(raw_forwarded)) !== null) {
            if (isValidIP(match[1])) ips.push(match[1]);
        }
    } else {
        const raw_xff = r.headersIn["X-Forwarded-For"];
        if (raw_xff) {
            let match;
            while ((match = split_xff.exec(raw_xff)) !== null) {
                if (isValidIP(match[0])) ips.push(match[0]);
            }
        }
    }
    ips.push(remote_addr);
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

    if (ip.split('::').length > 2) {
        return false;
    }

    let containsIPv4 = false;
    let v4DoubleColonSuffix = false;
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
            v4DoubleColonSuffix = true;
        } else {
            ip = ip.substring(0, lastColonIndex);
        }
    }

    let parts = [];
    const compressed_parts = ip.split('::');
    for (let i = 0; i < compressed_parts.length; i++) {
        const compressed_part = compressed_parts[i];
        if (compressed_part.length === 0) continue;
        parts = parts.concat(compressed_part.split(':'));
    }
    const expectedMaxGroups = containsIPv4 ? 6 : 8;
    if (ip.includes('::') || v4DoubleColonSuffix) {
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