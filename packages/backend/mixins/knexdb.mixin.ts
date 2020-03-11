import { KnexDbMixin as createKnexDBMixin } from 'moleculer-db-knex';
import { createKnexInstance, getKnexDbConfigs } from 'core/helpers';
import createHashIds from 'core/hashids';

const configs = getKnexDbConfigs();

export function KnexDBMixin(options: { schema: string; table: string; idField?: string }): any {
  const { schema, table, idField = 'id' } = options;
  const hashids = createHashIds(schema, 7);
  const instance: any = createKnexInstance();
  const knexDbMixin = createKnexDBMixin({
    schema,
    table,
    idField,
    knex: {
      configs,
      instance,
    },
  });
  knexDbMixin.methods = {
    ...knexDbMixin.methods,
    async nextval(seqNm: string): Promise<number> {
      const chunks: string[] = seqNm.split('.');
      let schemaNm: string = '';
      if (chunks.length > 2) {
        throw new Error('Sequence name MUST be follow format`: [schema_name][.]{sequence_name}');
      }
      if (chunks.length > 1) {
        seqNm = chunks[1];
        schemaNm = chunks[0] + '.';
      } else {
        seqNm = chunks[0];
      }
      const data = await this.knex().raw(`SELECT nextval(format('${schemaNm}%I', '${seqNm}')) as seq;`);
      const { rows } = data;
      return Number((rows && rows[0] && rows[0].seq) || 0);
    },

    encodeHex(entityId: number): string {
      return hashids.encodeHex(`${entityId}`);
    },

    decodeHex(code: string): number {
      return Number(hashids.decodeHex(code));
    },
  };
  return knexDbMixin;
}
