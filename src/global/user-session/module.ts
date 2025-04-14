import { Module } from '@nestjs/common';
import { RedisModule } from '@nestjs-modules/ioredis';

import { SecretsService } from '../secrets/service';
import { UserSessionService } from './service';

@Module({
  imports: [
    RedisModule.forRootAsync({
      useFactory: ({ userSessionRedis }: SecretsService) => {
        if (!userSessionRedis.REDIS_HOST) {
          throw new Error(
            'Invalid Redis configuration: REDIS_HOST is missing.',
          );
        }
        return {
          type: 'single',
          url: `redis://${userSessionRedis.REDIS_USER}:${userSessionRedis.REDIS_PASSWORD}@${userSessionRedis.REDIS_HOST}:${userSessionRedis.REDIS_PORT}`,
        };
      },
      inject: [SecretsService],
    }),
  ],
  providers: [UserSessionService],
  exports: [UserSessionService],
})
export class UserSessionModule {}
