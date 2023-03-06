import { NextFunction, Request, Response } from "express";
import * as zlib from "zlib";
import { hasRolePerm, RolePerms } from "./agent";

export function midVerify(req: Request, res: Response, next: NextFunction) {
    const hkey = req.header("X-Heimdall-MSAuth-HeaderKey");
    if (!hkey) {
        res.status(500).json({ "error": "Invalid X-Heimdall-MSAuth-HeaderKey" });
        return
    }
    if (hkey !== process.env.HEIMDALL_SESSION_HEADER_KEY) {
        res.status(500).json({ "error": "cannot trust Heimdall headers (hkey mismatch)" });
        return
    }
    const vjwt = req.header("X-Heimdall-MSAuth-ValidJWT");
    if (!vjwt || vjwt === "false") {
        next();
        return
    }
    next();
}

// this middleware is best used after midVerify
export function midValidJWT(req: Request, res: Response, next: NextFunction) {
    const vjwt = req.header("X-Heimdall-MSAuth-ValidJWT");
    if (!vjwt || vjwt === "false") {
        res.status(403).json({ "error": "invalid jwt" });
        return
    }
    next();
}

// this middleware is best used after midValidJWT
export function midValidCustomer(req: Request, res: Response, next: NextFunction) {
    const jwtt = req.header("X-Heimdall-MSAuth-JWT-Type");
    if (!jwtt || jwtt !== "customer") {
        res.status(401).json({ "error": "not logged in as a customer" });
        return
    }
    next();
}

export function newMidWithAgentPermission(role: string, perm: string): (req: Request, res: Response, next: NextFunction) => void {
    return (req: Request, res: Response, next: NextFunction) => {
        const groupData = req.header("X-Heimdall-MSAgent-GroupData")
        if (!groupData) {
            res.status(500).json({ "error": "missing group data" });
            return
        }
        const rawd = Buffer.from(groupData, "base64");
        zlib.inflate(rawd, (err, buffer) => {
            if (err) {
                res.status(500).json({ "error": "inflate error" });
                return
            }
            const jstr = buffer.toString("utf8");
            const rperms = JSON.parse(jstr) as RolePerms[];
            if (!hasRolePerm(role, perm, rperms)) {
                res.status(403).json({ "error": "not authorized (missing role or permission)" });
                return
            }
            next();
        })
    }
}

export function getStoreID(req: Request): string {
    const val = req.header("X-Heimdall-MSAuth-JWT-StoreID");
    if (!val) {
        return "";
    }
    return val;
}

export function getSessionID(req: Request): string {
    const val = req.header("X-Heimdall-MSAuth-JWT-SessionID");
    if (!val) {
        return "";
    }
    return val;
}

export function getCustomerID(req: Request): string {
    const val = req.header("X-Heimdall-MSAuth-JWT-CustomerID");
    if (!val) {
        return "";
    }
    return val;
}

export function getPowers(req: Request): string[] {
    const val = req.header("x-heimdall-msagent-powers")
    if (!val) {
        return [];
    }

    try{
        const bytesArr = Buffer.from(val, "base64");
        const inflated = zlib.inflateSync(bytesArr);
        const arr = JSON.parse(inflated.toString()) as string[];
        return arr;
    }
    catch(err){
        console.error(err);
        return [];
    }

}

export function isGuest(req: Request): boolean {
    const val = req.header("X-Heimdall-MSAuth-JWT-IsGuest");
    if (!val || val !== "1") {
        return false;
    }
    return true;
}

export function getAgentID(req: Request): string {
    const val = req.header("X-Heimdall-MSAuth-JWT-AgentID");
    if (!val) {
        return "";
    }
    return val;
}