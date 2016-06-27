import * as Koa from 'koa';
import * as pathToRegexp from 'path-to-regexp';
import Options = pathToRegexp.Options;
const Debug = require('debug');
const debug = Debug('koa-tiny-acl');

export class Acl {

    private static _instance: Acl;
    static get default(): Acl {
        return Acl._instance || (Acl._instance = new Acl());
    }

    constructor(private _entries?: Map<string, Entry>) {
        this._entries = this._entries || new Map<string, Entry>();
    }

    /**
     * @returns restriction from matching path
     */
    getRestrictions(url): string[] {
        if (!url) return null;
        for (let e of this._entries.values()) {
            if (e.re.test(url)) {
                return e.inclusiveList;
            }
        }
        return null;
    }

    /**
     * restrict access to path , to provided list
     */
    restrict = (path: string, inclusiveList: string[], opts?: Options) => {
        this._entries.set(path, {
            re: pathToRegexp(path, opts),
            inclusiveList: inclusiveList
        });
    }


    /**
     * 
     * Creates Middleware for target/claims
     * @template T 
     * @param {(ctx: Koa.Context) => T} target
     * @param {(x: T) => any[]} claims
     * @returns {KoaMiddleware}
     */
    create<T/*TR extends string|number|symbol*/>(
        target: (ctx: Koa.Context) => T,
        claims: (x: T) => any/*TR*/[],
        deny?: (ctx: AclContext, next?) => any): KoaMiddleware {
        //...    
        deny = deny || ((ctx: AclContext, next?): any => {
            //Can't throw ! why ?        
            ctx.status = 403;
        })

        let acl = this;

        function find<T>(restrictions: T[], claims: T[]): boolean {
            for (let restriction of restrictions) {
                if (claims.find(r => r == restriction)) {
                    return true;
                }
            }
            return false;
        }

        let setup = (ctx): AclContext => {
            ctx.acl = ctx.acl || acl;
            return ctx;
        }

        let hasAccess = (ctx: AclContext) => {

            let restrictions = ctx && ctx.acl ? ctx.acl.getRestrictions(ctx.url) : null;
            if (!restrictions) {
                return true;
            }

            let subject = target(ctx);
            if (!subject) {
                return false;
            }
            let _claims = claims(subject);
            const ok = find(restrictions, _claims);
            if (!ok) {
                let restrictions = ctx.acl.getRestrictions(ctx.path).join(',');
                debug(`access denied to subject: ${`${subject ? JSON.stringify(subject) : 'none'} \n`}` +
                    ` with claims:[${_claims ? _claims.join(',') : 'none'}] \n` +
                    ` for path: ${ctx.path}, with restrictions: ${restrictions} \n`)
            }
            return ok;
        }

        return function (ctx, next): void {
            if (hasAccess(setup(ctx))) {
                next();
                return;
            }
            deny(ctx, next);
        }
    };

}

export interface AclContext extends Koa.Context {
    acl?: Acl
}

export interface Entry {
    re: RegExp;
    inclusiveList: any[];
}

export type KoaNext = () => any
export type KoaMiddleware = (ctx: Koa.Context, KoaNext) => any;

