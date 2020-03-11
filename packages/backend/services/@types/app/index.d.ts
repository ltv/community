declare module 'app' {
  import moleculer, { GenericObject } from 'moleculer';
  export type ServiceMetadata = {
    orgId: number;
    usrId: number;
    user: any;
    roles: string[];
    token: string;
  };

  export class Context extends moleculer.Context<GenericObject, ServiceMetadata> {}
}
