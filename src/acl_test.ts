import {assert} from 'chai';
import * as request from 'supertest';
import * as Koa from 'koa';
import * as acl from './acl';
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

function auth(getUser: (name:string, pass:string)=> any ) : Koa.Middleware {
    
    let regex = /Basic\s+(.*)/i;    
    
    return async function(ctx, next)  {                
        
        let r =  regex.exec(ctx.headers['authentication']);
        if(!r) ctx.throw(401);

        let auth =   new Buffer(r[1], 'base64').toString();    
        if(!auth) ctx.throw(401);
        
        let parts = /^([^:]*):(.*)$/.exec(auth);
                             
        let user = getUser(parts[1], parts[2]);
        if(!user) ctx.throw(401);

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

describe('Restrict Access', () => {

    let app:Koa ; 

    beforeEach(() => {
        
        app = new Koa();

        // restrict user exists is users, sets ctx.user
        app.use(auth(findUser));

        // restrict user in 'role'
        app.use(acl.middleware(getUser, user => user.roles));

        //@restrict('admin')
        acl.restrict('/:name', ['admin']);
        let route = router.get('/:name', async function (name, next: Koa.Next) {
            let ctx: Koa.Context = this;
            ctx.status = 200;
            ctx.body = 'ok';
        })
        app.use(route);
    });


    it('200', (done) => {
        request(app.listen())
            .get('/bob')
            .set('Authentication', authorize('admin:admin'))
            .expect(200, done);
    });

    it('403', (done) => {
        request(app.listen())
            .get('/bob')
            .set('Authentication', authorize('bob:bob'))
            .expect(403, done);
    });

})
