import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { BookingService } from './booking.service';
import { BookingController } from './booking.controller';
import { Booking, BookingSchema } from './schemas/booking.schema';
import { Ride, RideSchema } from '../rides/schemas/ride.schema'; // Need RideModel
import { User, UserSchema } from '../user/schemas/user.schema'; // Need UserModel
// Import RidesModule or Service if needed for direct calls (e.g., check availability)
// Import PaymentModule later when needed

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Booking.name, schema: BookingSchema },
      { name: Ride.name, schema: RideSchema }, // Provide RideModel
      { name: User.name, schema: UserSchema }, // Provide UserModel
    ]),
    // RidesModule, // If needed
    // PaymentModule // Add later
  ],
  providers: [BookingService],
  controllers: [BookingController],
  exports: [BookingService], // Export if needed
})
export class BookingModule {}
