const chai = require('chai');

const chaiHttp = require('chai-http');

const server = require('../src/index');

chai.should();

chai.use(chaiHttp);

let user = '';

describe('Testing Identity Service', () => {
  describe('GET /system-health', () => {
    it('It should perform system health', (done) => {
      chai.request(server)
        .get('/system-health')
        .end((err, response) => {
          response.should.have.status(200);
          done();
        });
    });
  });

  describe('POST /user/authenticate', () => {
    it('It should authenticate user with correct email and password', (done) => {
      chai.request(server)
        .post('/user/authenticate')
        .send({ email: 'prasanna@gmail.com', password: 'PrasannaM@1122' })
        .end((err, response) => {
          response.should.have.status(200);
          response.body.should.be.a('object');
          const responseData = response.body.data;
          responseData.should.have.property('firstName');
          responseData.should.have.property('lastName');
          responseData.should.have.property('email').eq('prasanna@gmail.com');
          responseData.should.have.property('role');
          responseData.should.have.property('isBlocked');
          responseData.should.have.property('access');
          responseData.access.should.be.a('object');
          responseData.should.have.property('refresh');
          responseData.refresh.should.be.a('object');
          user = responseData;
          userId = responseData._id;
          done();
        });
    });

    it('It should not authenticate user with incorrect email', (done) => {
      chai.request(server)
        .post('/user/authenticate')
        .send({ email: 'prasnna@gmail.com', password: 'PrasannaM@1122' })
        .end((err, response) => {
          response.should.have.status(400);
          response.body.should.be.a('object');
          const responseData = response.body;
          responseData.should.have.property('title').eq('Bad Request');
          responseData.should.have.property('message').eq('Invalid email');
          responseData.should.have.property('info');
          responseData.info.should.be.a('object');
          done();
        });
    });

    it('It should not authenticate user with incorrect password', (done) => {
      chai.request(server)
        .post('/user/authenticate')
        .send({ email: 'prasanna@gmail.com', password: 'sannaM@1122' })
        .end((err, response) => {
          response.should.have.status(400);
          response.body.should.be.a('object');
          const responseData = response.body;
          responseData.should.have.property('title').eq('Bad Request');
          responseData.should.have.property('message').eq('Invalid password');
          responseData.should.have.property('info');
          responseData.info.should.be.a('object');
          done();
        });
    });
  });

  describe('POST /user/id2object', () => {
    it('It should not allow unauthenticated requests', (done) => {
      chai.request(server)
        .post('/user/id2object')
        .send({ ids: [userId], display: { firstName: 1, lastName: 1 } })
        .end((err, response) => {
          response.should.have.status(401);
          response.body.should.be.a('object');
          const responseData = response.body;
          responseData.should.have.property('title').eq('Unauthorized');
          responseData.should.have.property('message').eq('Authentication required');
          responseData.should.have.property('info');
          responseData.info.should.be.a('object');
          done();
        });
    });

    it('It should allow authenticated requests with correct data', (done) => {
      chai.request(server)
        .post('/user/id2object')
        .send({ ids: [user._id], display: { firstName: 1, lastName: 1, email: 1 } })
        .set('Authorization', user.access.token)
        .end((err, response) => {
          response.should.have.status(200);
          response.body.should.be.a('object');
          const responseData = response.body.data;
          responseData.should.be.a('array');
          responseData.forEach((e) => {
            e.should.have.property('firstName');
            e.should.have.property('lastName');
            e.should.have.property('email');
          });
          done();
        });
    });
  });

  describe('POST /user/refresh-token', () => {
    it('It should not allow invalid tokens', (done) => {
      chai.request(server)
        .post('/user/refresh-token')
        .send({ refresh: 'asd' })
        .end((err, response) => {
          response.should.have.status(401);
          response.body.should.be.a('object');
          const responseData = response.body;
          responseData.should.have.property('title').eq('Unauthorized');
          responseData.should.have.property('info');
          responseData.info.should.be.a('object');
          done();
        });
    });

    it('It should allow valid refresh token to generate the new access and refresh token', (done) => {
      chai.request(server)
        .post('/user/refresh-token')
        .send({ refresh: user.refresh.token })
        .end((err, response) => {
          response.should.have.status(200);
          response.body.should.be.a('object');
          const responseData = response.body.data;
          responseData.should.have.property('access');
          responseData.should.have.property('refresh');
          responseData.access.should.have.property('token');
          responseData.access.should.have.property('expires');
          responseData.refresh.should.have.property('token');
          responseData.refresh.should.have.property('expires');
          done();
        });
    });
  });

  describe('GET /user/profile', () => {
    it('It should not allow profile fetch without auth token', (done) => {
      chai.request(server)
        .get('/user/profile')
        .end((err, response) => {
          response.should.have.status(401);
          response.body.should.be.a('object');
          const responseData = response.body;
          responseData.should.have.property('title').eq('Unauthorized');
          responseData.should.have.property('info');
          responseData.info.should.be.a('object');
          done();
        });
    });

    it('It should allow featching user profile with auth token', (done) => {
      chai.request(server)
        .get('/user/profile')
        .set('Authorization', user.access.token)
        .end((err, response) => {
          response.should.have.status(200);
          response.body.should.be.a('object');
          const responseData = response.body.data;
          responseData.should.have.property('_id').eq(user._id);
          responseData.should.have.property('firstName').eq(user.firstName);
          responseData.should.have.property('lastName').eq(user.lastName);
          responseData.should.have.property('email').eq(user.email);
          done();
        });
    });
  });
});
