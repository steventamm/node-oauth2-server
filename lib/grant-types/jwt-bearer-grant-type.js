'use strict';

/*
 * Module dependencies.
 */

const AbstractGrantType = require('./abstract-grant-type');
const InvalidArgumentError = require('../errors/invalid-argument-error');
const InvalidGrantError = require('../errors/invalid-grant-error');
const InvalidRequestError = require('../errors/invalid-request-error');

/**
 * Decode a JWT's header and payload without signature verification.
 *
 * Returns { header, payload } on success, or null if the token is malformed.
 * This is intentionally unsafe — callers must verify the signature separately.
 */
function decodeJwtUnsafe(token) {
  try {
    const parts = token.split('.');
    if (parts.length < 3) return null;
    const decode = (s) => JSON.parse(
      Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')
    );
    return { header: decode(parts[0]), payload: decode(parts[1]) };
  } catch {
    return null;
  }
}

/**
 * JWT Bearer grant type.
 *
 * Implements RFC 7523 (JWT Profile for OAuth 2.0 Access Token Requests) as
 * applied to the Identity Assertion Authorization Grant (ID-JAG) defined in
 * draft-ietf-oauth-identity-assertion-authz-grant.
 *
 * This grant type enables Cross App Access: an upstream Identity Provider
 * issues an ID-JAG JWT which the client presents here (Resource AS) in
 * exchange for a standard Bearer access token.
 *
 * Grant type URI: urn:ietf:params:oauth:grant-type:jwt-bearer
 *
 * Register via extendedGrantTypes:
 *   new OAuth2Server({
 *     model,
 *     extendedGrantTypes: {
 *       'urn:ietf:params:oauth:grant-type:jwt-bearer': JwtBearerGrantType
 *     }
 *   });
 *
 * Options:
 *   model.getUserFromJwtBearer(assertion, header, payload, client)
 *     Validate the JWT assertion and return the associated user, or a falsy
 *     value on failure. Called with the raw assertion string plus the
 *     pre-decoded (unverified) header and payload so the model does not need
 *     to re-parse the JWT. The model is responsible for all cryptographic
 *     validation including:
 *       - Signature verification using the IdP's key (fetched from JWKS by
 *         header.kid / payload.iss, or a static key)
 *       - For ID-JAG: header.typ === 'oauth-id-jag+jwt'
 *       - payload.aud === this AS identifier
 *       - payload.client_id === client.id
 *       - payload.exp / payload.iat per RFC 7519
 *
 *   model.saveToken(token, client, user)
 *     Persist and return the issued access token.
 *
 *   shouldTrustIdentityProvider(header, payload) [optional]
 *     Called before the model with pre-decoded (unverified) JWT header and
 *     payload. Return truthy to allow the issuer, falsy to reject.
 *     Designed for runtime multi-issuer support — e.g. a database query keyed
 *     on payload.iss — without requiring a server restart.
 *     Because the claims have NOT been verified yet, this hook must not be
 *     treated as a security gate; final verification remains with the model.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7523
 * @see https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/
 */

class JwtBearerGrantType extends AbstractGrantType {
  constructor(options = {}) {
    if (!options.model) {
      throw new InvalidArgumentError('Missing parameter: `model`');
    }

    if (!options.model.getUserFromJwtBearer) {
      throw new InvalidArgumentError('Invalid argument: model does not implement `getUserFromJwtBearer()`');
    }

    if (!options.model.saveToken) {
      throw new InvalidArgumentError('Invalid argument: model does not implement `saveToken()`');
    }

    if (options.shouldTrustIdentityProvider !== undefined &&
        typeof options.shouldTrustIdentityProvider !== 'function') {
      throw new InvalidArgumentError('Invalid argument: `shouldTrustIdentityProvider` must be a function');
    }

    super(options);

    this.shouldTrustIdentityProvider = options.shouldTrustIdentityProvider || null;
  }

  /**
   * Handle JWT Bearer grant.
   *
   * @see https://www.rfc-editor.org/rfc/rfc7523#section-2.1
   */

  async handle(request, client) {
    if (!request) {
      throw new InvalidArgumentError('Missing parameter: `request`');
    }

    if (!client) {
      throw new InvalidArgumentError('Missing parameter: `client`');
    }

    const scope = this.getScope(request);
    const user = await this.getUserFromJwtBearer(request, client);

    return this.saveToken(user, client, scope);
  }

  /**
   * Retrieve the user from a JWT Bearer assertion.
   *
   * Pre-decodes the JWT to extract header and payload, optionally calls
   * shouldTrustIdentityProvider for runtime issuer lookup, then delegates
   * signature verification and user resolution to model.getUserFromJwtBearer().
   */

  async getUserFromJwtBearer(request, client) {
    const assertion = request.body.assertion;
    if (!assertion) {
      throw new InvalidRequestError('Missing parameter: `assertion`');
    }

    // Pre-decode header and payload without verifying the signature so we can
    // extract iss / kid / typ for issuer lookup before the model does crypto.
    const decoded = decodeJwtUnsafe(assertion);
    if (!decoded) {
      throw new InvalidGrantError('Invalid grant: assertion cannot be decoded');
    }

    const { header, payload } = decoded;

    // Optional runtime hook: lets callers resolve issuer config from a database
    // at request time without a server restart. Claims are NOT verified yet.
    if (this.shouldTrustIdentityProvider) {
      const trusted = await this.shouldTrustIdentityProvider(header, payload);
      if (!trusted) {
        throw new InvalidGrantError('Invalid grant: identity provider is not trusted');
      }
    }

    // Delegate signature verification and user resolution to the model.
    // Passing decoded header and payload avoids redundant JWT parsing.
    const user = await this.model.getUserFromJwtBearer(assertion, header, payload, client);

    if (!user) {
      throw new InvalidGrantError('Invalid grant: assertion is invalid');
    }

    return user;
  }

  /**
   * Save token.
   *
   * No refresh token is issued — this grant type represents client-to-client
   * federation; the client re-presents the upstream assertion to obtain a
   * new access token when needed.
   */

  async saveToken(user, client, requestedScope) {
    const validatedScope = await this.validateScope(user, client, requestedScope);
    const accessToken = await this.generateAccessToken(client, user, validatedScope);
    const accessTokenExpiresAt = this.getAccessTokenExpiresAt();

    const token = {
      accessToken,
      accessTokenExpiresAt,
      scope: validatedScope,
    };

    return this.model.saveToken(token, client, user);
  }
}

/*
 * Export constructor.
 */

module.exports = JwtBearerGrantType;
