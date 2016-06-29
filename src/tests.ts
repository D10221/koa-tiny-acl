import {assert} from 'chai';
import * as request from 'supertest';
import * as Koa from 'koa';
import {Acl, KoaMiddleware, KoaNext } from './acl';
import * as pathToRegexp from 'path-to-regexp';
import * as Debug from 'debug';
const compose = require('koa-compose');

const debug = Debug('koa-tiny-acl');


function decode(val) {
    val ? decodeURIComponent(val) : null;
}

class Router {

    get(path: string, action: (...args: any[]) => Promise<any>): (ctx, next) => Promise<any> {
        let re = pathToRegexp(path);
        return async (ctx: Koa.Context, next): Promise<any> => {
            let method = ctx.request.method;
            let url = ctx.request.url;
            let ok = re.test(url);
            debug('%s, %s, %s, %s -> %s', method, path, url, ok, re);
            if (method == 'GET' && ok) {
                action.apply(ctx, []);
                return next();
            }
            next();
        }
    }
}

const router = new Router();

// Users repo 
const users: User[] = [
    {
        name: 'admin', password: 'admin', email: 'admin@mail', roles: ['admin']
    },
    {
        name: 'bob', password: 'bob', email: 'bob@mail', roles: ['user']
    },
    {
        name: 'guest', password: 'guset', email: 'guest@mail' // , roles:[ 'user']
    }]

function findUser(name, pass) {
    return users.find(u => u.name == name && u.password == pass);
}

function authorize(credentials: string): string {
    return `Basic ${new Buffer(credentials).toString('Base64')}`;
}

function auth(getUser: (name: string, pass: string) => any): KoaMiddleware {

    let regex = /Basic\s+(.*)/i;

    return async function (ctx, next) {

        let r = regex.exec(ctx.headers['authentication']);
        if (!r) ctx.throw(401);

        let auth = new Buffer(r[1], 'base64').toString();
        if (!auth) ctx.throw(401);

        let parts = /^([^:]*):(.*)$/.exec(auth);

        let user = getUser(parts[1], parts[2]);
        if (!user) ctx.throw(401);

        (ctx.request as any).user = user;
        await next();
    }
}


class Auth {
    
    constructor(private getUser: (name: string, pass: string) => any) {
        
    }

    requireAuth(middleware: KoaMiddleware): KoaMiddleware {       
        return compose([auth(this.getUser), middleware]);
    }
}

//User definition 
export interface User {
    name?: string;
    password?: string;
    email?: string;
    roles?: string[];
}

let getUser = (ctx): User => {
    return ctx ? ctx.request.user : null
}


/**
 * go around bad d.ts 
 */
function listen(app) {
    return app.listen();
}


let acl = Acl.default;
const access = acl.create(getUser, user => user.roles);

/* Routes */
const dmz = router.get('/dmz/', async function (args, next) {
    this.body = 'ok';
});

acl.restrict('/users/:name*', ['admin']);


const unrestricted = router.get('/unrestricted', async function (a, n) {
    this.body = 'ok';
});

describe('acl', () => {

    // it('finds right restriction', () => {

    //     const acl = new Acl();
    //     acl.restrict('/a/:x*', ['x']);
    //     let x = acl.getRestrictions('/');
    //     assert.isTrue(!x);
    //     x = acl.getRestrictions('a');
    //     assert.isTrue(!x);
    //     x = acl.getRestrictions('/a');
    //     assert.deepEqual(x, ['x']);
    //     x = acl.getRestrictions('/a/?');
    //     assert.deepEqual(x, ['x']);
    // })

    it('200', async (done) => {

        let app = new Koa();
        //No Auth , no restriction 
        app.use(dmz)
        
        //@restrict('admin')    
        const restricted = router.get('/users/:name*', async function (name, next: KoaNext) {
            this.body = 'ok';
        });
        const a = new Auth(getUser);        
        app.use(a.requireAuth(restricted));

        // restrict user exists is users, sets ctx.user        
        // app.use(auth(findUser));
        // restrict user in 'role'
        app.use(access);
        
        //Auth but no restriction
        app.use(unrestricted);
        request(listen(app))
            .get('/users/bob')
            .set('Authentication', authorize('admin:admin'))
            .expect(200)
            .end((error, r) => {
                if (error) throw error;
                done()
            });
    });

    // it('403', (done) => {

    //     let app = new Koa();
    //     //No Auth , no restriction 
    //     app.use(dmz)
    //     // restrict user exists is users, sets ctx.user
    //     app.use(auth(findUser));
    //     // restrict user in 'role'
    //     app.use(access);
    //     //@restrict('admin')    
    //     app.use(router.get('/users/:name*', async function (name, next: KoaNext) {
    //         this.body = "ok";
    //     }));
    //     //Auth but no restriction
    //     app.use(unrestricted);

    //     request(listen(app))
    //         .get('/users/bob')
    //         .set('Authentication', authorize('bob:bob'))
    //         .expect(403)
    //         .end((error, r) => {
    //             if (error) throw error;
    //             done();
    //         });
    // });

    // it('dmz:200', (done) => {
    //     let app = new Koa();
    //     //No Auth , no restriction 
    //     app.use(dmz)
    //     // restrict user exists is users, sets ctx.user
    //     app.use(auth(findUser));
    //     // restrict user in 'role'
    //     app.use(access);

    //     request(listen(app))
    //         .get('/dmz')
    //         .expect(200)
    //         .end((error, r) => {
    //             if (error) throw error
    //             done();
    //         });
    // });

    // it('unrestricted:200', (done) => {


    //     let app = new Koa();
    //     //No Auth , no restriction 
    //     app.use(dmz)
    //     // restrict user exists is users, sets ctx.user
    //     app.use(auth(findUser));
    //     // restrict user in 'role'
    //     app.use(access);
    //     //@restrict('admin')    
    //     app.use(router.get('/users/:name*', async function (name, next: KoaNext) {
    //         this.body = "ok";
    //     }));
    //     //Auth but no restriction
    //     app.use(unrestricted);
    //     request(listen(app))
    //         // route added after with no restrictions after auht:middleware => requires auth , does not requires 'role' 
    //         .get('/unrestricted')
    //         .set('Authentication', authorize('bob:bob'))
    //         .expect(200)
    //         .end((error, r) => {
    //             if (error) throw error;
    //             done();
    //         });
    // });
})
