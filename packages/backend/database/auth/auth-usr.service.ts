import { Service, Method, Action } from 'moleculer-decorators';

import { BaseService } from 'utils/BaseService';
import { KnexDBMixin } from 'mixins/knexdb.mixin';
import { AUTH_USR, SCHEMA_AUTH } from 'utils/constants';
import { Context } from 'app';
import { HASH_ALGORITHM } from 'services/auth/helpers/constants';
import { sha512, genSalt, hashPass } from 'services/auth/helpers/password';

@Service({
  name: AUTH_USR,
  mixins: [
    KnexDBMixin({
      schema: SCHEMA_AUTH,
      table: AUTH_USR,
      idField: 'usrId',
    }),
  ],
  settings: {},
})
class AuthUsrService extends BaseService {
  /**
   * Check user existed or not by username & email
   *
   * @param username {string} username
   * @param email {string} email
   */
  @Action({
    params: {
      username: 'string',
      email: 'email',
    },
    cache: {
      keys: ['username', 'email'],
    },
  })
  async checkIsUserExisted(ctx: Context): Promise<boolean> {
    const { username, email } = ctx.params;
    const user = await this.db()
      .where('usrNm', username)
      .orWhere('usrEml', email)
      .select('*')
      .then(res => res && res[0]);
    return !!user;
  }

  /**
   * get User by Username
   *
   * @param usrNm {string}
   */
  @Action({
    name: 'getUserByUsername',
    params: {
      usrNm: 'string',
    },
    cache: {
      keys: ['usrNm'],
    },
  })
  async getUserByUsername(ctx: Context) {
    const { usrNm } = ctx.params;
    const user = await this.db()
      .where('usrNm', usrNm)
      .select('*')
      .then(res => res && res[0]);
    if (user) {
      return user;
    }
    return !!user;
  }

  @Action({
    name: 'createUser',
    params: {
      user: {
        type: 'object',
      },
    },
  })
  createUser(ctx: Context) {
    const user: any = ctx.params.user;
    const pwdSalt: string = genSalt();
    const usrPwd: string = hashPass(user.usrPwd, pwdSalt);

    return this.db()
      .insert({
        ...user,
        usrPwd,
        pwdSalt,
        pwdHashAlgo: HASH_ALGORITHM,
        emlConfToken: sha512(user.usrEml),
        emlVerified: false,
      })
      .returning(['usrId', 'usrNm', 'usrEml', 'orgId'])
      .then(res => res && res[0]);
  }

  @Action({
    name: 'createNewPassword',
    params: {
      userId: {
        type: 'number',
      },
      password: {
        type: 'string',
      },
    },
  })
  async createNewPassword(ctx: Context) {
    const { userId, password } = ctx.params;
    const passwordSalt: string = genSalt();
    const userPassword: string = hashPass(password, passwordSalt);

    const result = await ctx.call(`${AUTH_USR}.updateById`, {
      usrId: userId,
      entity: { usrPwd: userPassword, pwdSalt: passwordSalt },
    });

    if (result) {
      return true;
    }
    return false;
  }
}

export = AuthUsrService;
