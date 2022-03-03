
export interface RolePerms {
    r: string;
    p: string;
}

export function hasRolePerm(role: string, perm: string, rp: RolePerms[]): boolean {
    let finalPerm = perm;
    switch (finalPerm) {
        case "read":
            finalPerm = "r";
            break;
        case "write":
            finalPerm = "w";
            break;
        case "delete":
            finalPerm = "d";
            break;
        case "pp":
            finalPerm = "p";
            break;

    }
    for (const r of rp) {
        if (r.r !== role) {
            continue;
        }
        if (finalPerm === "" || finalPerm === "*" || r.p.indexOf(finalPerm) >= 0) {
            return true;
        }
    }
    return false;
} 