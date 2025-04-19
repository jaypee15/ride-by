import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { DriverService } from './driver.service';
import { DriverController } from './driver.controller';
import { Vehicle, VehicleSchema } from './schemas/vehicle.schema';
import { User, UserSchema } from '../user/schemas/user.schema'; // Needed to update User
import { Role, roleSchema } from '../user/schemas/role.schema'; // Needed to check role
import { AwsS3Module } from '../storage/s3-bucket.module';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Vehicle.name, schema: VehicleSchema },
      { name: User.name, schema: UserSchema }, // Import User schema
      { name: Role.name, schema: roleSchema }, // Import Role schema
    ]),
    AwsS3Module.forRoot('authAwsSecret'),
  ],
  providers: [DriverService],
  controllers: [DriverController],
  exports: [DriverService], // Export if needed by other modules
})
export class DriverModule {}
