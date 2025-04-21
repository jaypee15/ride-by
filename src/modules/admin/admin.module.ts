import { Module } from '@nestjs/common';
import { AdminService } from './admin.service';
import { AdminController } from './admin.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from '../user/schemas/user.schema';
import { Vehicle, VehicleSchema } from '../driver/schemas/vehicle.schema';
// Import AuthModule if guards depend on it and it's not global

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: Vehicle.name, schema: VehicleSchema },
    ]),
    // AuthModule, // If needed for guards
  ],
  providers: [AdminService],
  controllers: [AdminController],
})
export class AdminModule {}
