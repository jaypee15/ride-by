import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { RidesService } from './rides.service';
import { RidesController } from './rides.controller';
import { Ride, RideSchema } from './schemas/ride.schema';
import { Vehicle, VehicleSchema } from '../driver/schemas/vehicle.schema'; // Need VehicleModel
import { User, UserSchema } from '../user/schemas/user.schema'; // Need UserModel
import { GeolocationModule } from '../geolocation/geolocation.module';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Ride.name, schema: RideSchema },
      { name: Vehicle.name, schema: VehicleSchema }, // Provide VehicleModel
      { name: User.name, schema: UserSchema }, // Provide UserModel
    ]),
    GeolocationModule,
  ],
  providers: [RidesService],
  controllers: [RidesController],
  exports: [RidesService], // Export if needed
})
export class RidesModule {}
