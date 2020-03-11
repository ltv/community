import pick from 'lodash.pick';
import { Service, Action } from 'moleculer-decorators';
import { Errors } from 'moleculer';
import { Context } from 'app';

import { BaseService } from 'utils/BaseService';

import {
  ERR_USER_NOT_FOUND,
  ERR_ACCOUNT_NOT_VERIFIED,
  ERR_ACCOUNT_DISABLED,
  ERR_INVALID_TOKEN,
  ADM_USR,
} from 'utils/constants';
import { decode, getSigningKey, verifyJWT, AuthTokenPayload } from './helpers/jwt';

const { MoleculerClientError } = Errors;

@Service({
  name: 'auth0',
  mixins: [],
  settings: {},
})
class Auth0Service extends BaseService {
  /**
   * Get user by JWT token (for API GW authentication)
   *
   * @actions
   * @param {String} token - JWT token
   *
   * @returns {Object} Resolved user
   */
  @Action({
    cache: {
      keys: ['token'],
      ttl: 60 * 60 * 24 * 30, // 30 days
    },
    params: {
      token: 'string',
    },
  })
  async resolveToken(ctx: Context) {
    const { token: accessToken } = ctx.params;
    let dtoken: any;
    try {
      dtoken = decode(accessToken) || {};
    } catch (err) {
      throw new MoleculerClientError('Invalid token', 401, ERR_INVALID_TOKEN);
    }
    if (!dtoken || !dtoken.payload) throw new MoleculerClientError('Invalid token', 401, ERR_INVALID_TOKEN);

    const secret = await getSigningKey(dtoken);
    const payload: AuthTokenPayload = <AuthTokenPayload>verifyJWT(accessToken, secret, {});
    if (!payload) throw new MoleculerClientError('Invalid token', 401, ERR_INVALID_TOKEN);
    const authId = payload.sub.replace('auth0|', ''); // in case of auth0 provider

    const user: any = await ctx.call(`${ADM_USR}.getUserByAuthId`, { authId });
    if (!user) {
      throw new MoleculerClientError('User is not registered', 401, ERR_USER_NOT_FOUND);
    }

    if (!user.actFlg) {
      throw new MoleculerClientError('Please activate your account!', 401, ERR_ACCOUNT_NOT_VERIFIED);
    }

    if (user.delFlg) {
      throw new MoleculerClientError('User is disabled', 401, ERR_ACCOUNT_DISABLED);
    }

    return pick(user, ['usrId', 'usrNm', 'usrEml', 'actFlg', 'delFlg', 'regDt']);
  }

  @Action({
    name: 'signUp',
  })
  async actSignUp(ctx: Context) {
    const { email, id, type } = ctx.params;
    const data: any = await ctx.call(`${ADM_USR}.signUp`, { email, id, type });
    return {
      data,
    };
  }
}

export = Auth0Service;
