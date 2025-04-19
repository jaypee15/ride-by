import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { DatabaseModule } from './database/database.module';
import { RidesModule } from './rides/rides.module';
import { GeolocationModule } from './geolocation/geolocation.module';
import { DriverModule } from './driver/driver.module';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { MongooseModule } from '@nestjs/mongoose';
import { SecretsModule } from '../global/secrets/module';
import { SecretsService } from '../global/secrets/service';
import { AppModule } from './app.module';
import { GlobalModule } from 'src/global/global.module';
@Module({
  imports: [
    GlobalModule,
    DatabaseModule,
    ConfigModule,
    AuthModule,
    UserModule,
    RidesModule,
    DriverModule,
    GeolocationModule,
    AppModule,
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
export class MainModule {}
