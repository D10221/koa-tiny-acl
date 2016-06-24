import * as Koa from 'koa';
import * as pathToRegexp from 'path-to-regexp';
import Options = pathToRegexp.Options;


export interface Entry {
    re: RegExp,
    inclusiveList: any[]
}

export class Acl {

    private _entries: Map<string, Entry> = new Map<string, Entry>();

    /**
     * @returns restriction fro patching path 
     */
    restrictions(url): string[] {
        if (!url) return null;
        for (let e of this._entries.values()) {
            if (e.re.exec(url)) {
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
}

//default instance 
let acl: Acl = new Acl;

export const restrict = acl.restrict;

export interface AclContext extends Koa.Context {
    acl?: Acl
}

export function middleware<T>(target: (ctx: Koa.Context) => T, claims: (x: T) => any[]): any /*Koa.Middleware*/ {

    function find<T>(restrictions: T[], found: T[]) :boolean {
        for (let restriction of restrictions) {
            if (found.find(r => r == restriction)) {
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

        let restrictions = ctx && ctx.acl ? ctx.acl.restrictions(ctx.url) : null;
        if (!restrictions) return true;

        let subject = target(ctx);
        if (!subject) return false;

        return find(restrictions, claims(subject));;
    }

    return async function (ctx, next) {
                       
        if (hasAccess(setup(ctx))) {
            next();
        } else {
            //Can't throw ! why ? 
            return deny(ctx, next);
        }
    }
}

export let deny = (ctx:Koa.Context, next?) : any => {
    ctx.status = 403;
}
