import {assert} from 'chai';
import * as request from 'supertest';
import * as Koa from 'koa';
import {Acl} from './acl';
import * as pathToRegexp from 'path-to-regexp';
import * as router from 'koa-route-ts';

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
        next();
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

describe('restrictions', () => {

    it('finds right restriction', () => {
        const acl = new Acl();
        acl.restrict('/a/:x*', ['x']);
        let x = acl.restrictions('/');
        assert.isNull(x);
        x = acl.restrictions('a');
        assert.isNull(x);
        x = acl.restrictions('/a');
        assert.deepEqual(x, ['x']);
        x = acl.restrictions('/a/?');
        assert.deepEqual(x, ['x']);
    })
})

describe('Restrict Access', () => {

    let app = new Koa();
    let acl = Acl.default;

    //No Auth , no restriction 
    app.use(router.get('/dmz', function (args) {
        this.body = 'ok';
    }))

    // restrict user exists is users, sets ctx.user
    app.use(auth(findUser));

    // restrict user in 'role'
    app.use(acl.middleware(getUser, user => user.roles));

    //@restrict('admin')
    acl.restrict('/users/:name*', ['admin']);
    app.use(router.get('/users/:name*', async function (name, next: KoaNext) {
        let ctx: Koa.Context = this;
        ctx.status = 200;
        ctx.body = name;
    }));

    //Auth but no restriction
    app.use(router.get('/unrestricted', function (a, n) {
        this.body = 'ok';
    }));

    it('200', (done) => {
        request(app.listen())
            .get('/users/bob')
            .set('Authentication', authorize('admin:admin'))
            .expect(200)
            .expect('bob', done)});            

        it('403', (done) => {
            request(app.listen())
                .get('/users/bob')
                .set('Authentication', authorize('bob:bob'))
                .expect(403, done);
        });

        it('dmz:200', (done) => {
            request(app.listen())
                .get('/dmz')
                .expect(200, done);
        });

        it('unrestricted:200', (done) => {
            request(app.listen())
                // route added after with no restrictions after auht:middleware => requires auth , does not requires 'role' 
                .get('/unrestricted')
                .set('Authentication', authorize('bob:bob'))
                .expect(200, done);
        });

    })

    type KoaNext = () => any
    type KoaMiddleware = (ctx: Koa.Context, KoaNext) => any;