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
import { BookingModule } from './booking/booking.module';
import { RatingModule } from './rating/rating.module';
import { CommunicationModule } from './communication/communication.module';
import { AdminModule } from './admin/admin.module';
import { TripSharingModule } from './trip-sharing/trip-sharing.module';
import { NotificationModule } from './notification/notification.module';
import { SeedModule } from './seed/seed.module';
@Module({
  imports: [
    SeedModule,
    GlobalModule,
    DatabaseModule,
    ConfigModule,
    AuthModule,
    UserModule,
    RidesModule,
    DriverModule,
    GeolocationModule,
    AppModule,
    BookingModule,
    RatingModule,
    CommunicationModule,
    AdminModule,
    UserModule,
    TripSharingModule,
    NotificationModule,
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
