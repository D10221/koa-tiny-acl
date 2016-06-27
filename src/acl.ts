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
    restrictions(url): string[] {
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

    middleware = <T>(target: (ctx: Koa.Context) => T, claims: (x: T) => any[]): any /*Koa.Middleware*/ => {
        
        let self = this;

        function find<T>(restrictions: T[], claims: T[]): boolean {
            for (let restriction of restrictions) {
                if (claims.find(r => r == restriction)) {
                    return true;
                }
            }
            return false;
        }

        let setup = (ctx): AclContext => {
            ctx.acl = ctx.acl || self;
            return ctx;
        }

        let hasAccess = (ctx: AclContext) => {

            let restrictions = ctx && ctx.acl ? ctx.acl.restrictions(ctx.url) : null;
            if (!restrictions) {
                return true;
            }

            let subject = target(ctx);
            if (!subject) {
                return false;
            }
            let _claims = claims(subject);
            const ok = find(restrictions, _claims);
            if(!ok){
                let restrictions = ctx.acl.restrictions(ctx.path).join(',');                        
                console.log(`access denied to subject: ${`${subject ? JSON.stringify(subject): 'none'} \n`} with claims:[${_claims ? _claims.join(','): 'none'}] for path: ${ctx.path}, with restrictions: ${restrictions}`)
            }
            return ok;            
        }

        return function (ctx, next) :void {
            if (hasAccess(setup(ctx))) {
                next();
                return;
            }            
            //Can't throw ! why ?
            self.deny(ctx, next);
        }
    };

    deny = (ctx: AclContext, next?): any => {        
        ctx.status = 403;
    }
}

export interface AclContext extends Koa.Context {
    acl?: Acl
}

export interface Entry {
    re: RegExp,
    inclusiveList: any[]
}

 