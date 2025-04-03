import { Global, Module } from '@nestjs/common';

import { SecretsModule } from './secrets/module';
import { UserSessionModule } from './user-session/module';
import { TokenHelper } from './utils/token.utils';

@Global()
@Module({
  imports: [SecretsModule, UserSessionModule],
  providers: [TokenHelper],
  exports: [SecretsModule, TokenHelper, UserSessionModule],
})
export class GlobalModule {}
