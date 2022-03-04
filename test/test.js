const chai = require('chai');

const chaiHttp = require('chai-http');

const server = require('../src/index');

chai.should();

chai.use(chaiHttp);

describe('GET /system-health', () => {
  it('It should authenticate user info', (done) => {
    chai.request(server)
      .get('/system-health')
      .end((err, response) => {
        response.should.have.status(200);
        done();
      });
  });
});

describe('GET /user/authenticate', () => {
  it('It should authenticate user info', (done) => {
    chai.request(server)
      .post('/user/authenticate')
      .send({ email: 'prasanna@gmail.com', password: 'PrasannaM@1122' })
      .end((err, response) => {
        console.log(err);
        console.log(response.body);
        response.should.have.status(200);
        done();
      });
  });
});
