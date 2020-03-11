import fs from 'fs';
import path from 'path';
import jwt from 'jsonwebtoken';
import jwksRsa from 'jwks-rsa';

import { UnauthorizedError } from './errors';

const ROOT_PATH = process.cwd();
const { JWT_PUBLIC_KEY_PATH, JWT_PRIVATE_KEY_PATH } = process.env;

const { AUTH0_DOMAIN, AUTH0_AUDIENCE, AUTH0_CLIENT_ID } = process.env;
const DEFAULT_REVOKED_FUNCTION = function(_: any, __: any, cb: (p: any, p1: any) => void) {
  return cb(null, false);
};

/**
 * Sign JWT Key with Public & Private Key
 *
 * @param type string refreshToken || undefined
 * @param payload { [key: string]: any }
 * @param expiredIn expressed in seconds or a string describing a time span zeit/ms.
 */
export function generateToken(type: string, payload: { [key: string]: any }, expiresIn: string) {
  const keyPath = path.isAbsolute(JWT_PRIVATE_KEY_PATH)
    ? JWT_PRIVATE_KEY_PATH
    : path.resolve(ROOT_PATH, JWT_PRIVATE_KEY_PATH);
  const privateKEY = fs.readFileSync(keyPath, 'utf8');

  // TODO: Change this later
  const baseOpts = {
    issuer: 'LTV Co., Ltd',
    subject: 'admin@ltv.vn',
    audience: 'https://ltv.vn',
  };

  const signOptions = {
    ...baseOpts,
    expiresIn,
    algorithm: 'RS256',
  };

  return jwt.sign(payload, privateKEY, signOptions);
}

function getPublicKey(): string {
  const keyPath = path.isAbsolute(JWT_PUBLIC_KEY_PATH)
    ? JWT_PUBLIC_KEY_PATH
    : path.resolve(ROOT_PATH, JWT_PUBLIC_KEY_PATH);
  return fs.readFileSync(keyPath, 'utf8');
}

function getVerifyOptions() {
  const baseOpts = {
    issuer: 'LTV Co., Ltd',
    subject: 'admin@ltv.vn',
    audience: 'https://ltv.vn',
  };

  return {
    ...baseOpts,
    algorithm: ['RS256'],
  };
}

/**
 * Verify a JWT token and return the decoded payload
 *
 * @param {String} token
 */
export function verifyJWT(token: string, publicKEY?: string, verifyOptions?: any) {
  if (!!!publicKEY) {
    publicKEY = getPublicKey();
  }

  if (!!!verifyOptions) {
    verifyOptions = getVerifyOptions();
  }

  try {
    return jwt.verify(token, publicKEY, verifyOptions);
  } catch (err) {
    return false;
  }
}

export function decode(token: string) {
  return jwt.decode(token, { complete: true });
}

/** ----- auth0 ----- */

const jwkClient = jwksRsa({
  cache: true,
  cacheMaxEntries: 5,
  jwksUri: `https://${AUTH0_DOMAIN}/.well-known/jwks.json`,
  strictSsl: false,
  cacheMaxAge: 60 * 60 * 24,
});

export interface AuthTokenHeader {
  typ: string;
  alg: string;
  kid: string;
}

export interface AuthTokenPayload {
  iss: string;
  sub: string;
  aud: string[];
  iat: number;
  exp: number;
  azp: string;
  scope: string;
}

export interface AuthToken {
  header: AuthTokenHeader;
  payload: {};
  signature: string;
}

export function getSigningKey(token: AuthToken): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    jwkClient.getSigningKey(token.header.kid, (err: any, key: any) => {
      if (err) {
        return reject(err);
      }
      return resolve(key.publicKey || key.rsaPublicKey);
    });
  });
}

export function checkRevoked(decoded: AuthToken, revokedCallback?: (p: any, p1: any) => void): Promise<AuthToken> {
  const isRevokedCallback = revokedCallback || DEFAULT_REVOKED_FUNCTION;
  return new Promise<AuthToken>((resolve, reject) => {
    isRevokedCallback(null, decoded.payload, function(err, revoked) {
      if (err) {
        return reject(err);
      } else if (revoked) {
        return reject(new UnauthorizedError('revoked_token', { message: 'The token has been revoked.' }));
      } else {
        return resolve(decoded);
      }
    });
  });
}
