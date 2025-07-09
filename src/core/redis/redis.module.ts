import {
  RedisModule as RedisCoreModule,
  RedisModuleOptions,
} from '@nestjs-modules/ioredis';
import { SecretsService } from 'src/global/secrets/service';

export class RedisModule {
  static forRoot(secretKey: keyof SecretsService) {
    return RedisCoreModule.forRootAsync({
      inject: [SecretsService],
      useFactory: (secretsService: SecretsService): RedisModuleOptions => {
        const config = secretsService[secretKey];
        return {
          type: 'single',
          url: `redis://${config.REDIS_USERNAME}:${config.REDIS_PASSWORD}@${config.REDIS_HOST}:${config.REDIS_PORT}`,
        };
      },
    });
  }
}
