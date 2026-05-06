// Type definitions for Node OAuth2 Server 5.0
// Definitions by:  Robbie Van Gorkom <https://github.com/vangorra>,
//                  Charles Irick <https://github.com/cirick>,
//                  Daniel Fischer <https://github.com/d-fischer>,
//                  Vitor Santos <https://github.com/rvitorsantos>

import * as http from 'http';

/**
 * Represents an OAuth2 server instance.
 */
declare class OAuth2Server {
    static OAuth2Server: typeof OAuth2Server;

    options: OAuth2Server.ServerOptions;

    /**
     * Instantiates OAuth2Server using the supplied model
     */
    constructor(options: OAuth2Server.ServerOptions);

    /**
     * Authenticates a request.
     */
    authenticate(
        request: OAuth2Server.Request,
        response: OAuth2Server.Response,
        options?: OAuth2Server.AuthenticateOptions
    ): Promise<OAuth2Server.Token>;

    /**
     * Authorizes a token request.
     */
    authorize(
        request: OAuth2Server.Request,
        response: OAuth2Server.Response,
        options?: OAuth2Server.AuthorizeOptions
    ): Promise<OAuth2Server.AuthorizationCode>;

    /**
     * Retrieves a new token for an authorized token request.
     */
    token(
        request: OAuth2Server.Request,
        response: OAuth2Server.Response,
        options?: OAuth2Server.TokenOptions
    ): Promise<OAuth2Server.Token>;
}

declare namespace OAuth2Server {
    /**
     * Represents an incoming HTTP request.
     */
    class Request {
        body?: any;
        headers?: Record<string, string>;
        method?: string;
        query?: Record<string, string>;

        /**
         * Instantiates Request using the supplied options.
         *
         */
        constructor(options: {
            headers: Record<string, string>,
            method: string,
            query: Record<string, string>,
            body?: any
        } & Record<string, any> | http.IncomingMessage);

        /**
         * Returns the specified HTTP header field. The match is case-insensitive.
         *
         */
        get(field: string): any | undefined;

        /**
         * Checks if the request’s Content-Type HTTP header matches any of the given MIME types.
         *
         */
        is(types: string[]): string | false;
    }

    /**
     * Represents an outgoing HTTP response.
     */
    class Response {
        body?: any;
        headers?: Record<string, string>;
        status?: number;

        /**
         * Instantiates Response using the supplied options.
         *
         */
        constructor(options?: Record<string, any> | http.ServerResponse);

        /**
         * Returns the specified HTTP header field. The match is case-insensitive.
         *
         */
        get(field: string): any | undefined;

        /**
         * Sets the specified HTTP header field. The match is case-insensitive.
         *
         */
        set(field: string, value: string): void;

        /**
         * Redirects to the specified URL using 302 Found.
         *
         */
        redirect(url: string): void;
    }

    /**
     * Pre-decoded JWT header passed to getUserFromJwtBearer and
     * shouldTrustIdentityProvider. The signature has NOT been verified.
     */
    interface JwtBearerHeader {
        alg: string;
        /** For ID-JAG assertions this must equal 'oauth-id-jag+jwt'. */
        typ?: string;
        /** Key ID for JWKS key selection. */
        kid?: string;
        [key: string]: unknown;
    }

    /**
     * Pre-decoded JWT payload passed to getUserFromJwtBearer and
     * shouldTrustIdentityProvider. The signature has NOT been verified.
     */
    interface JwtBearerPayload {
        /** Issuer — identifies the IdP; use for JWKS / key lookup. */
        iss?: string;
        /** Subject — the user identity asserted by the IdP. */
        sub?: string;
        /** Audience — must match this AS's identifier. */
        aud?: string | string[];
        exp?: number;
        iat?: number;
        jti?: string;
        /** For ID-JAG: must match the authenticated client's id. */
        client_id?: string;
        [key: string]: unknown;
    }

    /**
     * Constructor options for JwtBearerGrantType.
     */
    interface JwtBearerGrantTypeOptions {
        model: JwtBearerModel;
        accessTokenLifetime: number;
        refreshTokenLifetime?: number;
        /**
         * Optional runtime hook for multi-issuer support.
         *
         * Called with the pre-decoded (unverified) JWT header and payload before
         * model.getUserFromJwtBearer(). Return truthy to allow this issuer,
         * falsy to reject with invalid_grant.
         *
         * Intended for database-backed issuer trust lookups at request time so
         * new customer IDPs can be added without a server restart.
         *
         * Because the claims are NOT yet verified, this hook must not be used
         * as the sole security gate — cryptographic verification must still
         * happen inside model.getUserFromJwtBearer().
         *
         * @example
         *   shouldTrustIdentityProvider: async (header, payload) => {
         *     const idp = await db.findTrustedIdP(payload.iss);
         *     return idp != null;
         *   }
         */
        shouldTrustIdentityProvider?: (
            header: JwtBearerHeader,
            payload: JwtBearerPayload
        ) => Promise<boolean | null | undefined> | boolean | null | undefined;
    }

    /**
     * JWT Bearer grant type (RFC 7523 / ID-JAG Cross App Access).
     *
     * Accepts a JWT Bearer assertion — typically an ID-JAG issued by an upstream
     * Identity Provider — and exchanges it for a standard Bearer access token.
     *
     * Register via extendedGrantTypes:
     *   extendedGrantTypes: {
     *     'urn:ietf:params:oauth:grant-type:jwt-bearer': JwtBearerGrantType
     *   }
     *
     * Required model methods: getUserFromJwtBearer, saveToken
     */
    class JwtBearerGrantType extends AbstractGrantType {
        constructor(options: JwtBearerGrantTypeOptions);
        handle(request: Request, client: Client): Promise<Token | Falsey>;
    }

    abstract class AbstractGrantType {
        /**
         * Instantiates AbstractGrantType using the supplied options.
         *
         */
        constructor(options: TokenOptions)

        /**
         * Generate access token. Calls Model#generateAccessToken() if implemented.
         *
         */
        generateAccessToken(client: Client, user: User, scope: string[]): Promise<string>;

        /**
         * Generate refresh token. Calls Model#generateRefreshToken() if implemented.
         *
         */
        generateRefreshToken(client: Client, user: User, scope: string[]): Promise<string>;

        /**
         * Get access token expiration date.
         *
         */
        getAccessTokenExpiresAt(): Date;

        /**
         * Get refresh token expiration date.
         *
         */
        getRefreshTokenExpiresAt(): Date;

        /**
         * Get scope from the request body.
         *
         */
        getScope(request: Request): string[];

        /**
         * Validate requested scope. Calls Model#validateScope() if implemented.
         *
         */
        validateScope(user: User, client: Client, scope?: string[]): Promise<string[] | Falsey>;

        /**
         * Retrieve info from the request and client and return token
         *
         */
        abstract handle(request: Request, client: Client): Promise<Token | Falsey>;
    }

    interface ServerOptions extends AuthenticateOptions, AuthorizeOptions, TokenOptions {
        /**
         * Model object
         */
        model: AuthorizationCodeModel | ClientCredentialsModel | RefreshTokenModel | PasswordModel | ExtensionModel;
    }

    interface AuthenticateOptions {
        /**
         * The scope(s) to authenticate.
         */
        scope?: string[];

        /**
         * Set the X-Accepted-OAuth-Scopes HTTP header on response objects.
         */
        addAcceptedScopesHeader?: boolean;

        /**
         * Set the X-OAuth-Scopes HTTP header on response objects.
         */
        addAuthorizedScopesHeader?: boolean;

        /**
         * Allow clients to pass bearer tokens in the query string of a request.
         */
        allowBearerTokensInQueryString?: boolean;
    }

    interface AuthorizeOptions {
        /**
         * The authenticate handler
         */
        authenticateHandler?: {};

        /**
         * Allow clients to specify an empty state
         */
        allowEmptyState?: boolean;

        /**
         * Lifetime of generated authorization codes in seconds (default = 5 minutes).
         */
        authorizationCodeLifetime?: number;
    }

    interface TokenOptions {
        /**
         * Lifetime of generated access tokens in seconds (default = 1 hour)
         */
        accessTokenLifetime?: number;

        /**
         * Lifetime of generated refresh tokens in seconds (default = 2 weeks)
         */
        refreshTokenLifetime?: number;

        /**
         * Allow extended attributes to be set on the returned token
         */
        allowExtendedTokenAttributes?: boolean;

        /**
         * Require a client secret. Defaults to true for all grant types.
         */
        requireClientAuthentication?: Record<string, boolean>;

        /**
         * Always revoke the used refresh token and issue a new one for the refresh_token grant.
         */
        alwaysIssueNewRefreshToken?: boolean;

        /**
         * Additional supported grant types.
         */
        extendedGrantTypes?: Record<string, typeof AbstractGrantType>;
    }

    /**
     * For returning falsey parameters in cases of failure
     */
    type Falsey = '' | 0 | false | null | undefined;

    interface BaseModel {
        /**
         * Invoked to generate a new access token.
         *
         */
        generateAccessToken?(client: Client, user: User, scope: string[]): Promise<string>;

        /**
         * Invoked to retrieve a client using a client id or a client id/client secret combination, depending on the grant type.
         *
         */
        getClient(clientId: string, clientSecret: string): Promise<Client | Falsey>;

        /**
         * Invoked to save an access token and optionally a refresh token, depending on the grant type.
         *
         */
        saveToken(token: Token, client: Client, user: User): Promise<Token | Falsey>;
    }

    interface RequestAuthenticationModel {
        /**
         * Invoked to retrieve an existing access token previously saved through Model#saveToken().
         *
         */
        getAccessToken(accessToken: string): Promise<Token | Falsey>;

        /**
         * Invoked during request authentication to check if the provided access token was authorized the requested scopes.
         * Optional, if a custom authenticateHandler is used or if there is no scope part of the request.
         *
         */
        verifyScope?(token: Token, scope: string[]): Promise<boolean>;
    }

    interface AuthorizationCodeModel extends BaseModel, RequestAuthenticationModel {
        /**
         * Invoked to generate a new refresh token.
         *
         */
        generateRefreshToken?(client: Client, user: User, scope: string[]): Promise<string>;

        /**
         * Invoked to generate a new authorization code.
         *
         */
        generateAuthorizationCode?(client: Client, user: User, scope: string[]): Promise<string>;

        /**
         * Invoked to retrieve an existing authorization code previously saved through Model#saveAuthorizationCode().
         *
         */
        getAuthorizationCode(authorizationCode: string): Promise<AuthorizationCode | Falsey>;

        /**
         * Invoked to save an authorization code.
         *
         */
        saveAuthorizationCode(
          code: Pick<AuthorizationCode, 'authorizationCode' | 'expiresAt' | 'redirectUri' | 'scope' | 'codeChallenge' | 'codeChallengeMethod'>,
          client: Client,
          user: User
        ): Promise<AuthorizationCode | Falsey>;

        /**
         * Invoked to revoke an authorization code.
         *
         */
        revokeAuthorizationCode(code: AuthorizationCode): Promise<boolean>;

        /**
         * Invoked to check if the requested scope is valid for a particular client/user combination.
         *
         */
        validateScope?(user: User, client: Client, scope?: string[]): Promise<string[] | Falsey>;

        /**
         * Invoked to check if the provided `redirectUri` is valid for a particular `client`.
         *
         */
        validateRedirectUri?(redirect_uri: string, client: Client): Promise<boolean>;
    }

    interface PasswordModel extends BaseModel, RequestAuthenticationModel {
        /**
         * Invoked to generate a new refresh token.
         *
         */
        generateRefreshToken?(client: Client, user: User, scope: string[]): Promise<string>;

        /**
         * Invoked to retrieve a user using a username/password combination.
         *
         */
        getUser(username: string, password: string, client: Client): Promise<User | Falsey>;

        /**
         * Invoked to check if the requested scope is valid for a particular client/user combination.
         *
         */
        validateScope?(user: User, client: Client, scope?: string[]): Promise<string[] | Falsey>;
    }

    interface RefreshTokenModel extends BaseModel, RequestAuthenticationModel {
        /**
         * Invoked to generate a new refresh token.
         *
         */
        generateRefreshToken?(client: Client, user: User, scope: string[]): Promise<string>;

        /**
         * Invoked to retrieve an existing refresh token previously saved through Model#saveToken().
         *
         */
        getRefreshToken(refreshToken: string): Promise<RefreshToken | Falsey>;

        /**
         * Invoked to revoke a refresh token.
         *
         */
        revokeToken(token: RefreshToken): Promise<boolean>;
    }

    interface ClientCredentialsModel extends BaseModel, RequestAuthenticationModel {
        /**
         * Invoked to retrieve the user associated with the specified client.
         *
         */
        getUserFromClient(client: Client): Promise<User | Falsey>;

        /**
         * Invoked to check if the requested scope is valid for a particular client/user combination.
         *
         */
        validateScope?(user: User, client: Client, scope?: string[]): Promise<string[] | Falsey>;
    }

    interface ExtensionModel extends BaseModel, RequestAuthenticationModel {}

    /**
     * Model interface for the JWT Bearer grant type (RFC 7523 / ID-JAG).
     *
     * Used with the `urn:ietf:params:oauth:grant-type:jwt-bearer` grant to
     * implement the Resource AS role in Cross App Access flows.
     */
    interface JwtBearerModel extends BaseModel, RequestAuthenticationModel {
        /**
         * Invoked to validate a JWT Bearer assertion and return the associated user.
         *
         * The framework pre-decodes the JWT and provides the decoded (unverified)
         * header and payload alongside the raw assertion string. Using header.kid
         * and payload.iss the model can select the correct JWKS key without
         * re-parsing the token.
         *
         * The model is responsible for all cryptographic validation:
         *   - Verify the IdP signature (fetch JWKS by payload.iss, select key by
         *     header.kid, or use a static key for the issuer)
         *   - For ID-JAG: verify header.typ === 'oauth-id-jag+jwt'
         *   - Verify payload.aud matches this AS's identifier
         *   - Verify payload.client_id matches client.id
         *   - Verify payload.exp and payload.iat per RFC 7519
         *
         * Return the user object on success, or a falsy value to reject the grant.
         */
        getUserFromJwtBearer(
            assertion: string,
            decodedHeader: JwtBearerHeader,
            decodedPayload: JwtBearerPayload,
            client: Client
        ): Promise<User | Falsey>;

        /**
         * Invoked to check if the requested scope is valid for the user/client pair.
         */
        validateScope?(user: User, client: Client, scope?: string[]): Promise<string[] | Falsey>;
    }

    /**
     * An interface representing the user.
     * A user object is completely transparent to oauth2-server and is simply used as input to model functions.
     */
    interface User {
        [key: string]: any;
    }

    /**
     * An interface representing the client and associated data
     */
    interface Client {
        id: string;
        redirectUris?: string | string[];
        grants: string | string[];
        accessTokenLifetime?: number;
        refreshTokenLifetime?: number;
        [key: string]: any;
    }

    /**
     * An interface representing the authorization code and associated data.
     */
    interface AuthorizationCode {
        authorizationCode: string;
        expiresAt: Date;
        redirectUri: string;
        scope?: string[];
        client: Client;
        user: User;
        codeChallenge?: string;
        codeChallengeMethod?: string;
        [key: string]: any;
    }

    /**
     * An interface representing the token(s) and associated data.
     */
    interface Token {
        accessToken: string;
        accessTokenExpiresAt?: Date;
        refreshToken?: string;
        refreshTokenExpiresAt?: Date;
        scope?: string[];
        client: Client;
        user: User;
        [key: string]: any;
    }

    /**
     * An interface representing the refresh token and associated data.
     */
    interface RefreshToken {
        refreshToken: string;
        refreshTokenExpiresAt?: Date;
        scope?: string[];
        client: Client;
        user: User;
        [key: string]: any;
    }

    class OAuthError extends Error {
        constructor(messageOrError: string | Error, properties?: object);

        /**
         * The HTTP error code.
         */
        code: number;

        /**
         * The OAuth error code.
         */
        name: string;

        /**
         * A human-readable error message.
         */
        message: string;
    }

    class AccessDeniedError extends OAuthError {}
    class InsufficientScopeError extends OAuthError {}
    class InvalidArgumentError extends OAuthError {}
    class InvalidClientError extends OAuthError {}
    class InvalidGrantError extends OAuthError {}
    class InvalidRequestError extends OAuthError {}
    class InvalidScopeError extends OAuthError {}
    class InvalidTokenError extends OAuthError {}
    class ServerError extends OAuthError {}
    class UnauthorizedClientError extends OAuthError {}
    class UnauthorizedRequestError extends OAuthError {}
    class UnsupportedGrantTypeError extends OAuthError {}
    class UnsupportedResponseTypeError extends OAuthError {}
}

export = OAuth2Server;
