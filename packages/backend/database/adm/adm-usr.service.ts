import { Service, Action, Method } from 'moleculer-decorators';

import { BaseService } from 'utils/BaseService';
import { KnexDBMixin } from 'mixins/knexdb.mixin';
import { ADM_USR, SCHEMA_ADM } from 'utils/constants';
import { Context } from 'app';

@Service({
  name: ADM_USR,
  mixins: [
    KnexDBMixin({
      schema: SCHEMA_ADM,
      table: ADM_USR,
      idField: 'usrId',
    }),
  ],
  settings: {},
})
class AdmUsrService extends BaseService {
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

  @Action({
    params: {
      usrId: {
        type: 'number',
        optional: true,
      },
    },
    cache: {
      keys: ['usrId'],
    },
  })
  async findById(ctx: Context): Promise<any> {
    const { usrId } = ctx.params;
    if (!usrId) {
      return null;
    }
    try {
      const res = await this.find({ usrId });
      return res && res.length ? res[0] : null;
    } catch (e) {
      this.logger.error(e);
      return null;
    }
  }

  /**
   * get User by AuthId
   *
   * @param authId {string}
   */
  @Action({
    name: 'getUserByAuthId',
    params: {
      authId: 'string',
    },
    cache: {
      keys: ['authId'],
    },
  })
  async getUserByAuthId(ctx: Context) {
    const { authId } = ctx.params;
    const user = await this.db()
      .where('authId', authId)
      .select('*')
      .then(res => res && res[0]);
    if (user) {
      return user;
    }
    return !!user;
  }

  @Action({})
  async signUp(ctx: Context) {
    const { email, id, type } = ctx.params;
    return this.signUpMethod(email, id, type);
  }

  @Method
  signUpMethod(email: string, id: string, type: string) {
    return this.db()
      .insert({
        usrNm: email,
        usrEml: email,
        verifyEml: false,
        authId: id,
        type,
        orgId: 1,
      })
      .returning('*')
      .then(res => res && res[0]);
  }
}

export = AdmUsrService;
