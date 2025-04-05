import { Module } from '@nestjs/common';
import { RedisModule, RedisModuleOptions } from '@nestjs-modules/ioredis';

import { SecretsService } from '../secrets/service';
import { UserSessionService } from './service';

@Module({
  imports: [
    RedisModule.forRootAsync({
      useFactory: ({ userSessionRedis }: SecretsService) => {
        return {
          config: {
            host: userSessionRedis.REDIS_HOST,
            port: userSessionRedis.REDIS_PORT,
            username: userSessionRedis.REDIS_USER,
            password: userSessionRedis.REDIS_PASSWORD,
          },
        } as unknown as RedisModuleOptions;
      },
      inject: [SecretsService],
    }),
  ],
  providers: [UserSessionService],
  exports: [UserSessionService],
})
export class UserSessionModule {}
