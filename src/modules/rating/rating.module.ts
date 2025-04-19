import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { RatingService } from './rating.service';
import { RatingController } from './rating.controller';
import { Rating, RatingSchema } from './schemas/rating.schema';
import { Booking, BookingSchema } from '../booking/schemas/booking.schema'; // Need BookingModel
import { User, UserSchema } from '../user/schemas/user.schema'; // Need UserModel

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Rating.name, schema: RatingSchema },
      { name: Booking.name, schema: BookingSchema }, // To verify booking status/ownership
      { name: User.name, schema: UserSchema }, // To update user average ratings
    ]),
  ],
  providers: [RatingService],
  controllers: [RatingController],
  exports: [RatingService],
})
export class RatingModule {}
