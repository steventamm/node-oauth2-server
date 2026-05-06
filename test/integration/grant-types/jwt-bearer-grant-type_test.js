'use strict';

/**
 * Module dependencies.
 */

const JwtBearerGrantType = require('../../../lib/grant-types/jwt-bearer-grant-type');
const InvalidArgumentError = require('../../../lib/errors/invalid-argument-error');
const InvalidGrantError = require('../../../lib/errors/invalid-grant-error');
const InvalidRequestError = require('../../../lib/errors/invalid-request-error');
const Request = require('../../../lib/request');
const should = require('chai').should();

/**
 * A minimal syntactically-valid JWT used in tests.
 * The header and payload are real base64url-encoded JSON; the signature is
 * fake. The grant type pre-decodes but does NOT verify — that's the model's job.
 */
const encode = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
const TEST_JWT_HEADER = { alg: 'RS256', typ: 'oauth-id-jag+jwt', kid: 'key-1' };
const TEST_JWT_PAYLOAD = {
  iss: 'https://idp.example.com',
  sub: 'user-123',
  aud: 'https://as.example.com',
  client_id: 'client-id',
  exp: Math.floor(Date.now() / 1000) + 300,
  iat: Math.floor(Date.now() / 1000),
};
const ASSERTION = `${encode(TEST_JWT_HEADER)}.${encode(TEST_JWT_PAYLOAD)}.fakesig`;

/**
 * Test `JwtBearerGrantType` integration.
 */

describe('JwtBearerGrantType integration', function() {
  describe('constructor()', function() {
    it('should throw an error if `model` is missing', function() {
      try {
        new JwtBearerGrantType();

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Missing parameter: `model`');
      }
    });

    it('should throw an error if the model does not implement `getUserFromJwtBearer()`', function() {
      try {
        new JwtBearerGrantType({ model: {} });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Invalid argument: model does not implement `getUserFromJwtBearer()`');
      }
    });

    it('should throw an error if the model does not implement `saveToken()`', function() {
      try {
        const model = {
          getUserFromJwtBearer: function() {}
        };

        new JwtBearerGrantType({ model: model });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Invalid argument: model does not implement `saveToken()`');
      }
    });

    it('should throw an error if `shouldTrustIdentityProvider` is not a function', function() {
      try {
        const model = { getUserFromJwtBearer: function() {}, saveToken: function() {} };
        new JwtBearerGrantType({ accessTokenLifetime: 120, model: model, shouldTrustIdentityProvider: 'not-a-function' });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Invalid argument: `shouldTrustIdentityProvider` must be a function');
      }
    });

    it('should not throw an error when `model` implements required methods', function() {
      const model = {
        getUserFromJwtBearer: function() {},
        saveToken: function() {}
      };

      new JwtBearerGrantType({ accessTokenLifetime: 120, model: model });
    });

    it('should not throw an error when `shouldTrustIdentityProvider` is a function', function() {
      const model = { getUserFromJwtBearer: function() {}, saveToken: function() {} };
      new JwtBearerGrantType({
        accessTokenLifetime: 120,
        model: model,
        shouldTrustIdentityProvider: async () => true
      });
    });
  });

  describe('handle()', function() {
    it('should throw an error if `request` is missing', async function() {
      const model = {
        getUserFromJwtBearer: function() {},
        saveToken: function() {}
      };
      const grantType = new JwtBearerGrantType({ accessTokenLifetime: 120, model: model });

      try {
        await grantType.handle();

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Missing parameter: `request`');
      }
    });

    it('should throw an error if `client` is missing', async function() {
      const model = {
        getUserFromJwtBearer: function() {},
        saveToken: function() {}
      };
      const grantType = new JwtBearerGrantType({ accessTokenLifetime: 120, model: model });
      const request = new Request({ body: { assertion: ASSERTION }, headers: {}, method: {}, query: {} });

      try {
        await grantType.handle(request);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Missing parameter: `client`');
      }
    });

    it('should throw an error if `assertion` is missing from request body', async function() {
      const model = {
        getUserFromJwtBearer: function() {},
        saveToken: function() {}
      };
      const grantType = new JwtBearerGrantType({ accessTokenLifetime: 120, model: model });
      const request = new Request({ body: {}, headers: {}, method: {}, query: {} });

      try {
        await grantType.handle(request, {});

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal('Missing parameter: `assertion`');
      }
    });

    it('should throw an error if the assertion is rejected by the model', async function() {
      const model = {
        getUserFromJwtBearer: async function() { return null; },
        saveToken: function() {}
      };
      const grantType = new JwtBearerGrantType({ accessTokenLifetime: 120, model: model });
      const request = new Request({
        body: { assertion: ASSERTION },
        headers: {},
        method: {},
        query: {}
      });

      try {
        await grantType.handle(request, {});

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidGrantError);
        e.message.should.equal('Invalid grant: assertion is invalid');
      }
    });

    it('should return a token', async function() {
      const token = {};
      const client = { id: 'client-id' };
      const user = { id: 'user-id' };
      const scope = ['read'];

      const model = {
        getUserFromJwtBearer: async function(_assertion, _header, _payload, _client) {
          _assertion.should.equal(ASSERTION);
          _header.should.deep.equal(TEST_JWT_HEADER);
          _payload.should.deep.equal(TEST_JWT_PAYLOAD);
          _client.should.deep.equal(client);
          return { ...user };
        },
        saveToken: async function(_token, _client, _user) {
          _client.should.deep.equal(client);
          _user.should.deep.equal(user);
          _token.accessToken.should.equal('long-access-token-hash');
          _token.accessTokenExpiresAt.should.be.instanceOf(Date);
          _token.scope.should.eql(scope);
          should.not.exist(_token.refreshToken);
          return token;
        },
        validateScope: async function(_user, _client, _scope) {
          _user.should.deep.equal(user);
          _client.should.deep.equal(client);
          _scope.should.eql(scope);
          return scope;
        },
        generateAccessToken: async function(_client, _user, _scope) {
          _client.should.deep.equal(client);
          _user.should.deep.equal(user);
          _scope.should.eql(scope);
          return 'long-access-token-hash';
        }
      };

      const grantType = new JwtBearerGrantType({ accessTokenLifetime: 120, model: model });
      const request = new Request({
        body: { assertion: ASSERTION, scope: scope.join(' ') },
        headers: {},
        method: {},
        query: {}
      });

      const data = await grantType.handle(request, client);
      data.should.equal(token);
    });

    it('should not include a refresh token in the saved token', async function() {
      const client = { id: 'client-id' };
      const user = { id: 'user-id' };

      const model = {
        getUserFromJwtBearer: async function() { return user; },
        saveToken: async function(_token) {
          should.not.exist(_token.refreshToken);
          should.not.exist(_token.refreshTokenExpiresAt);
          return _token;
        }
      };

      const grantType = new JwtBearerGrantType({ accessTokenLifetime: 120, model: model });
      const request = new Request({
        body: { assertion: ASSERTION },
        headers: {},
        method: {},
        query: {}
      });

      await grantType.handle(request, client);
    });

    it('should support promises', function() {
      const token = {};
      const model = {
        getUserFromJwtBearer: async function() { return {}; },
        saveToken: async function() { return token; }
      };
      const grantType = new JwtBearerGrantType({ accessTokenLifetime: 120, model: model });
      const request = new Request({
        body: { assertion: ASSERTION },
        headers: {},
        method: {},
        query: {}
      });

      grantType.handle(request, {}).should.be.an.instanceOf(Promise);
    });

    it('should support non-promises', function() {
      const token = {};
      const model = {
        getUserFromJwtBearer: function() { return {}; },
        saveToken: function() { return token; }
      };
      const grantType = new JwtBearerGrantType({ accessTokenLifetime: 120, model: model });
      const request = new Request({
        body: { assertion: ASSERTION },
        headers: {},
        method: {},
        query: {}
      });

      grantType.handle(request, {}).should.be.an.instanceOf(Promise);
    });
  });

  describe('getUserFromJwtBearer()', function() {
    it('should throw an error if `assertion` is missing', async function() {
      const model = {
        getUserFromJwtBearer: function() {},
        saveToken: () => should.fail()
      };
      const grantType = new JwtBearerGrantType({ accessTokenLifetime: 120, model: model });
      const request = new Request({ body: {}, headers: {}, method: {}, query: {} });

      try {
        await grantType.getUserFromJwtBearer(request, {});

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal('Missing parameter: `assertion`');
      }
    });

    it('should throw an error if the assertion cannot be decoded', async function() {
      const model = {
        getUserFromJwtBearer: () => should.fail('model should not be called for malformed assertions'),
        saveToken: () => should.fail()
      };
      const grantType = new JwtBearerGrantType({ accessTokenLifetime: 120, model: model });
      const request = new Request({
        body: { assertion: 'not.a.jwt' },
        headers: {},
        method: {},
        query: {}
      });

      try {
        await grantType.getUserFromJwtBearer(request, {});

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidGrantError);
        e.message.should.equal('Invalid grant: assertion cannot be decoded');
      }
    });

    it('should throw an error if the model returns a falsy user', function() {
      const model = {
        getUserFromJwtBearer: function() { return null; },
        saveToken: () => should.fail()
      };
      const grantType = new JwtBearerGrantType({ accessTokenLifetime: 120, model: model });
      const request = new Request({
        body: { assertion: ASSERTION },
        headers: {},
        method: {},
        query: {}
      });

      return grantType.getUserFromJwtBearer(request, {})
        .then(should.fail)
        .catch(function(e) {
          e.should.be.an.instanceOf(InvalidGrantError);
          e.message.should.equal('Invalid grant: assertion is invalid');
        });
    });

    it('should return a user', function() {
      const user = { id: 'user-id' };
      const model = {
        getUserFromJwtBearer: function() { return user; },
        saveToken: () => should.fail()
      };
      const grantType = new JwtBearerGrantType({ accessTokenLifetime: 120, model: model });
      const request = new Request({
        body: { assertion: ASSERTION },
        headers: {},
        method: {},
        query: {}
      });

      return grantType.getUserFromJwtBearer(request, {})
        .then(function(data) {
          data.should.equal(user);
        })
        .catch(should.fail);
    });

    it('should pass assertion, decoded header, decoded payload, and client to model', async function() {
      const client = { id: 'my-client' };
      let capturedArgs;

      const model = {
        getUserFromJwtBearer: function(assertion, header, payload, c) {
          capturedArgs = { assertion, header, payload, client: c };
          return { id: 'user' };
        },
        saveToken: () => should.fail()
      };
      const grantType = new JwtBearerGrantType({ accessTokenLifetime: 120, model: model });
      const request = new Request({
        body: { assertion: ASSERTION },
        headers: {},
        method: {},
        query: {}
      });

      await grantType.getUserFromJwtBearer(request, client);
      capturedArgs.assertion.should.equal(ASSERTION);
      capturedArgs.header.should.deep.equal(TEST_JWT_HEADER);
      capturedArgs.payload.should.deep.equal(TEST_JWT_PAYLOAD);
      capturedArgs.client.should.equal(client);
    });

    it('should support promises', function() {
      const user = { id: 'user-id' };
      const model = {
        getUserFromJwtBearer: async function() { return user; },
        saveToken: () => should.fail()
      };
      const grantType = new JwtBearerGrantType({ accessTokenLifetime: 120, model: model });
      const request = new Request({
        body: { assertion: ASSERTION },
        headers: {},
        method: {},
        query: {}
      });

      grantType.getUserFromJwtBearer(request, {}).should.be.an.instanceOf(Promise);
    });

    it('should support non-promises', function() {
      const user = { id: 'user-id' };
      const model = {
        getUserFromJwtBearer: function() { return user; },
        saveToken: () => should.fail()
      };
      const grantType = new JwtBearerGrantType({ accessTokenLifetime: 120, model: model });
      const request = new Request({
        body: { assertion: ASSERTION },
        headers: {},
        method: {},
        query: {}
      });

      grantType.getUserFromJwtBearer(request, {}).should.be.an.instanceOf(Promise);
    });
  });

  describe('shouldTrustIdentityProvider', function() {
    it('should be called with decoded header and payload before the model', async function() {
      const client = {};
      const user = { id: 'user-id' };
      let capturedHeader, capturedPayload;

      const model = {
        getUserFromJwtBearer: async function() { return user; },
        saveToken: async function(_token) { return _token; }
      };
      const grantType = new JwtBearerGrantType({
        accessTokenLifetime: 120,
        model: model,
        shouldTrustIdentityProvider: function(header, payload) {
          capturedHeader = header;
          capturedPayload = payload;
          return true;
        }
      });
      const request = new Request({ body: { assertion: ASSERTION }, headers: {}, method: {}, query: {} });

      await grantType.getUserFromJwtBearer(request, client);
      capturedHeader.should.deep.equal(TEST_JWT_HEADER);
      capturedPayload.should.deep.equal(TEST_JWT_PAYLOAD);
    });

    it('should reject with invalid_grant when it returns false', async function() {
      const model = {
        getUserFromJwtBearer: () => should.fail('model should not be called when issuer is untrusted'),
        saveToken: function() {}
      };
      const grantType = new JwtBearerGrantType({
        accessTokenLifetime: 120,
        model: model,
        shouldTrustIdentityProvider: async () => false
      });
      const request = new Request({ body: { assertion: ASSERTION }, headers: {}, method: {}, query: {} });

      try {
        await grantType.getUserFromJwtBearer(request, {});

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidGrantError);
        e.message.should.equal('Invalid grant: identity provider is not trusted');
      }
    });

    it('should reject with invalid_grant when it returns null', async function() {
      const model = {
        getUserFromJwtBearer: () => should.fail('model should not be called when issuer is untrusted'),
        saveToken: function() {}
      };
      const grantType = new JwtBearerGrantType({
        accessTokenLifetime: 120,
        model: model,
        shouldTrustIdentityProvider: async () => null
      });
      const request = new Request({ body: { assertion: ASSERTION }, headers: {}, method: {}, query: {} });

      try {
        await grantType.getUserFromJwtBearer(request, {});

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidGrantError);
        e.message.should.equal('Invalid grant: identity provider is not trusted');
      }
    });

    it('should proceed when it returns true', async function() {
      const user = { id: 'user-id' };
      const model = {
        getUserFromJwtBearer: async function() { return user; },
        saveToken: async function(_token) { return _token; }
      };
      const grantType = new JwtBearerGrantType({
        accessTokenLifetime: 120,
        model: model,
        shouldTrustIdentityProvider: async () => true
      });
      const request = new Request({ body: { assertion: ASSERTION }, headers: {}, method: {}, query: {} });

      const result = await grantType.getUserFromJwtBearer(request, {});
      result.should.equal(user);
    });

    it('should support async database-style lookups', async function() {
      const user = { id: 'user-id' };
      // Simulates a DB that knows about one issuer.
      const trustedIssuers = new Map([['https://idp.example.com', { jwksUri: 'https://idp.example.com/.well-known/jwks.json' }]]);

      const model = {
        getUserFromJwtBearer: async function() { return user; },
        saveToken: async function(_token) { return _token; }
      };
      const grantType = new JwtBearerGrantType({
        accessTokenLifetime: 120,
        model: model,
        shouldTrustIdentityProvider: async (_header, payload) => trustedIssuers.has(payload.iss)
      });

      // Known issuer — should succeed.
      const request = new Request({ body: { assertion: ASSERTION }, headers: {}, method: {}, query: {} });
      const result = await grantType.getUserFromJwtBearer(request, {});
      result.should.equal(user);

      // Unknown issuer — should reject.
      const unknownPayload = { ...TEST_JWT_PAYLOAD, iss: 'https://untrusted.example.com' };
      const unknownAssertion = `${encode(TEST_JWT_HEADER)}.${encode(unknownPayload)}.fakesig`;
      const request2 = new Request({ body: { assertion: unknownAssertion }, headers: {}, method: {}, query: {} });

      try {
        await grantType.getUserFromJwtBearer(request2, {});
        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidGrantError);
        e.message.should.equal('Invalid grant: identity provider is not trusted');
      }
    });
  });

  describe('saveToken()', function() {
    it('should save the token without a refresh token', async function() {
      const token = {};
      const model = {
        getUserFromJwtBearer: () => should.fail(),
        saveToken: function(_token, _client, _user) {
          should.not.exist(_token.refreshToken);
          return token;
        },
        validateScope: function() { return ['foo']; }
      };
      const grantType = new JwtBearerGrantType({ accessTokenLifetime: 123, model: model });
      const data = await grantType.saveToken({}, {}, ['foo']);
      data.should.equal(token);
    });

    it('should support promises', function() {
      const token = {};
      const model = {
        getUserFromJwtBearer: () => should.fail(),
        saveToken: async function() { return token; }
      };
      const grantType = new JwtBearerGrantType({ accessTokenLifetime: 123, model: model });

      grantType.saveToken({}, {}, []).should.be.an.instanceOf(Promise);
    });

    it('should support non-promises', function() {
      const token = {};
      const model = {
        getUserFromJwtBearer: () => should.fail(),
        saveToken: function() { return token; }
      };
      const grantType = new JwtBearerGrantType({ accessTokenLifetime: 123, model: model });

      grantType.saveToken({}, {}, []).should.be.an.instanceOf(Promise);
    });
  });
});
