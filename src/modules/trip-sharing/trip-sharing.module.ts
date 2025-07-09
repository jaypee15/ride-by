import { Module } from '@nestjs/common';
import { TripSharingService } from './trip-sharing.service';
import { TripSharingController } from './trip-sharing.controller';
import { RedisModule } from '@nestjs-modules/ioredis'; // Needs Redis access
import { MongooseModule } from '@nestjs/mongoose';
import { Ride, RideSchema } from '../rides/schemas/ride.schema';
import { SecretsService } from 'src/global/secrets/service'; // Needed for Redis config

@Module({
  imports: [
    // Configure Redis specifically for this module or rely on global
    RedisModule.forRootAsync({
      useFactory: ({ userSessionRedis }: SecretsService) => ({
        // Reuse userSessionRedis config or create separate one
        type: 'single',
        url: `redis://${userSessionRedis.REDIS_USER}:${userSessionRedis.REDIS_PASSWORD}@${userSessionRedis.REDIS_HOST}:${userSessionRedis.REDIS_PORT}`,
      }),
      inject: [SecretsService],
    }),
    MongooseModule.forFeature([
      { name: Ride.name, schema: RideSchema }, // Need RideModel
    ]),
  ],
  providers: [TripSharingService],
  controllers: [TripSharingController],
})
export class TripSharingModule {}
