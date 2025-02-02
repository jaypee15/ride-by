import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { DatabaseModule } from './modules/database/database.module';
import { RidesModule } from './modules/rides/rides.module';
import { GeolocationModule } from './modules/geolocation/geolocation.module';
import { RidersModule } from './modules/riders/riders.module';
import { AuthModule } from './modules/auth/auth.module';
import { UsersModule } from './modules/users/users.module';
import { MongooseModule } from '@nestjs/mongoose';
import { SecretsModule } from './global/secrets/module';
import { SecretsService } from './global/secrets/service';
@Module({
  imports: [
    DatabaseModule,
    ConfigModule,
    AuthModule,
    UsersModule,
    RidesModule,
    RidersModule,
    GeolocationModule,
    MongooseModule.forRootAsync({
      imports: [SecretsModule],
      inject: [SecretsService],
      useFactory: (secretsService: SecretsService) => ({
        uri: secretsService.MONGO_URI,
      }),
    }),
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
