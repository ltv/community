import pick from 'lodash.pick';
import { Context } from 'app';
import { Service, Action, Method } from 'moleculer-decorators';
import { Errors } from 'moleculer';

import {
  AUTH_USR,
  SERVICE_AUTH,
  AUTH_TOKEN,
  ERR_USER_NOT_FOUND,
  ERR_ACCOUNT_NOT_VERIFIED,
  ERR_ACCOUNT_DISABLED,
  ERR_USR_OR_EML_EXISTED,
  ERR_INVALID_TOKEN,
  ADM_SUBS,
  ADM_USR,
  VALIDATION_ERROR,
} from 'utils/constants';
import { CacheCleaner } from 'mixins/cache.cleaner.mixin';
import { comparePassword } from './helpers/password';
import { BaseService } from 'utils/BaseService';
import { generateToken, verifyJWT } from './helpers/jwt';

const { MoleculerClientError } = Errors;

const name = SERVICE_AUTH;

@Service({
  name,
  mixins: [CacheCleaner([])],
  settings: {},
})
class AuthUserService extends BaseService {
  @Action({
    name: 'createUser',
    params: {
      usrNm: 'string',
      usrEml: {
        type: 'email',
      },
      usrPwd: 'string',
    },
  })
  async actCreateUser(ctx: Context) {
    const { usrNm, usrEml, usrPwd } = ctx.params;
    const isUserExisted = await ctx.call(`${AUTH_USR}.checkIsUserExisted`, { usrNm, usrEml });

    if (!isUserExisted) {
      const user: any = {
        usrNm,
        usrEml,
        usrPwd,
      };

      return ctx.call(`${AUTH_USR}.createUser`, { user });
    }

    throw new MoleculerClientError('User Or Email already existed', 400, ERR_USR_OR_EML_EXISTED, {
      user: {
        usrNm,
        usrEml,
      },
    });
  }

  @Action({
    name: 'login',
    params: {
      username: 'string',
      password: 'string',
    },
  })
  async actLogin(ctx: Context) {
    const { username, password } = ctx.params;
    const token = await this.login(username, password);
    return {
      data: {
        token,
      },
    };
  }

  @Action({
    name: 'subscription',
    params: {
      email: 'email',
      title: 'string',
      content: 'string',
      _token: 'string',
    },
  })
  async actSubscription(ctx: Context) {
    const { email, _token, title, content } = ctx.params;
    if (!_token || _token != '$2b$10$GkRfmpthBxuUdsEqrZFQbezwLYLfkD8jRD/dzRQA0Jm97ejWdr5x.') {
      throw new MoleculerClientError('TOKEN NOT FOUND', 400, ERR_ACCOUNT_NOT_VERIFIED);
    }
    const subs = await this.broker.call(`${ADM_SUBS}.newSubscription`, { email, title, content });
    return {
      data: {
        subs,
      },
    };
  }

  @Action({
    name: 'deleteToken',
    params: {
      usrId: 'number',
      token: 'string',
    },
  })
  async actDeleteToken(ctx: Context) {
    const { usrId, token } = ctx.params;
    return this.deleteToken(usrId, token);
  }

  /**
   * Login with username and password
   *
   * @param username {string}
   * @param password {string}
   */
  @Method
  async login(username: string, password: string) {
    const user: any = await this.broker.call(`${AUTH_USR}.getUserByUsername`, { usrNm: username });
    console.log('TCL: AuthUserService -> login -> user', user);

    // Check User existed
    if (!user) {
      throw new MoleculerClientError('User or password is invalid', 400, ERR_USER_NOT_FOUND);
    }

    // Check verified
    if (!user.actFlg) {
      throw new MoleculerClientError('Please activate your account!', 400, ERR_ACCOUNT_NOT_VERIFIED);
    }

    // Check status
    if (user.delFlg) {
      throw new MoleculerClientError('Account is disabled!', 400, ERR_ACCOUNT_DISABLED);
    }

    const isValid = comparePassword(password, user.usrPwd);
    console.log('TCL: AuthUserService -> login -> isValid', isValid);
    if (isValid) {
      const token = generateToken('newToken', { user: pick(user, ['usrId', 'usrNm']) }, '30 days');
      return this.saveToken(user.usrId, token, user.orgId).then(() => token);
    }
    return Promise.reject(new MoleculerClientError('Username or password is invalid!', 422));
  }

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
    const decoded: any = verifyJWT(ctx.params.token);
    if (!decoded || !decoded.user) throw new MoleculerClientError('Invalid token', 401, ERR_INVALID_TOKEN);

    const user: any = await ctx.call(`${AUTH_USR}.getUserByUsername`, { usrNm: decoded.user.usrNm });
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
    graphql: {
      mutation: 'changePassword(input: ChangePasswordInput!): ChangePasswordPayload',
    },
    params: {
      input: {
        type: 'object',
        props: {
          oldPassword: 'string',
          newPassword: 'string',
        },
      },
    },
  })
  async changePassword(ctx: Context) {
    const errorMessage = 'An error occurs while making the request, please contact administrator to get help!';

    try {
      const { oldPassword, newPassword } = ctx.params.input;

      if (!oldPassword || !newPassword) {
        return new MoleculerClientError('Parameters validation error!', 422, VALIDATION_ERROR);
      }

      const { usrId: currentUserId } = ctx.meta.user;

      const findUser: any[] = await ctx.call(`${ADM_USR}.find`, { where: { usrId: currentUserId, actFlg: true } });

      const currentUser = findUser ? findUser[0] : null;

      if (!currentUser) {
        return {
          message: errorMessage,
        };
      }
      const { usrEml } = currentUser;

      const result: any[] = await ctx.call(`${AUTH_USR}.find`, { where: { usrEml, actFlg: true } });
      const usr = result ? result[0] : null;

      if (!usr) {
        return {
          message: errorMessage,
        };
      }

      const { usrPwd: oldHassedPwd, usrId: userId } = usr;
      const compareRes = comparePassword(oldPassword, oldHassedPwd);

      if (!compareRes) {
        return new MoleculerClientError('Wrong Password', 422, 'Wrong Password');
      }

      const createNewPasswordResult = await ctx.call(`${AUTH_USR}.createNewPassword`, {
        userId,
        password: newPassword,
      });

      if (createNewPasswordResult) {
        return {
          message: 'Your password has been changed successfully!',
        };
      }
      return {
        message: errorMessage,
      };
    } catch (error) {
      this.logger.error(error);
      return {
        message: errorMessage,
      };
    }
  }

  /**
   * Save Token to database
   *
   * @param usrId {number}
   * @param authToken {string}
   */
  @Method
  saveToken(usrId: number, authToken: string, orgId: number) {
    return this.broker.call(`${AUTH_TOKEN}.insert`, { entity: { usrId, authToken, orgId } });
  }

  /**
   * Delete token by usrId & token
   *
   * @param usrId {number}
   * @param token {string}
   */
  @Method
  deleteToken(usrId: number, token: string) {
    // 1. Delete Token from cache
    this.delCache(`resolveToken:${token}`);
    // 2. Delete Token from database
    return this.broker.call(`${AUTH_TOKEN}.deleteToken`, { usrId, token });
  }
}
export = AuthUserService;
