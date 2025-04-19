import { Injectable, Logger, HttpException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import mongoose, { Model } from 'mongoose'; // Import ClientSession
import { Rating, RatingDocument } from './schemas/rating.schema';
import { Booking, BookingDocument } from '../booking/schemas/booking.schema';
import { User, UserDocument } from '../user/schemas/user.schema';
import { SubmitRatingDto } from './dto/submit-rating.dto';
import { BookingStatus } from '../booking/enums/booking-status.enum';
import { RoleRatedAs } from './enums/role-rated-as.enum';
import { ErrorHelper } from 'src/core/helpers';

@Injectable()
export class RatingService {
  private readonly logger = new Logger(RatingService.name);

  constructor(
    @InjectModel(Rating.name) private ratingModel: Model<RatingDocument>,
    @InjectModel(Booking.name) private bookingModel: Model<BookingDocument>,
    @InjectModel(User.name) private userModel: Model<UserDocument>,
  ) {}

  async submitRating(
    raterId: string,
    dto: SubmitRatingDto,
  ): Promise<RatingDocument> {
    this.logger.log(
      `User ${raterId} attempting to submit rating for booking ${dto.bookingId}`,
    );
    if (!mongoose.Types.ObjectId.isValid(dto.bookingId)) {
      ErrorHelper.BadRequestException('Invalid Booking ID format.');
    }

    const session = await this.ratingModel.db.startSession(); // Use transaction for rating + user update
    session.startTransaction();

    try {
      // 1. Find the booking and verify rater involvement and booking status
      const booking = await this.bookingModel
        .findById(dto.bookingId)
        .session(session);
      if (!booking) {
        ErrorHelper.NotFoundException(
          `Booking with ID ${dto.bookingId} not found.`,
        );
      }

      if (booking.status !== BookingStatus.COMPLETED) {
        ErrorHelper.BadRequestException(
          `Cannot rate a booking that is not completed (status: ${booking.status}).`,
        );
      }

      let rateeId: string;
      let roleRatedAs: RoleRatedAs;
      let userUpdateFieldPrefix:
        | 'averageRatingAsDriver'
        | 'averageRatingAsPassenger';
      let userUpdateCountField:
        | 'totalRatingsAsDriver'
        | 'totalRatingsAsPassenger';
      let alreadyRatedField: 'passengerRated' | 'driverRated';

      if (booking.passenger.toString() === raterId) {
        // Passenger is rating the driver
        rateeId = booking.driver.toString();
        roleRatedAs = RoleRatedAs.DRIVER;
        userUpdateFieldPrefix = 'averageRatingAsDriver';
        userUpdateCountField = 'totalRatingsAsDriver';
        alreadyRatedField = 'passengerRated';
        if (booking.passengerRated) {
          ErrorHelper.ConflictException(
            'You have already rated the driver for this booking.',
          );
        }
      } else if (booking.driver.toString() === raterId) {
        // Driver is rating the passenger
        rateeId = booking.passenger.toString();
        roleRatedAs = RoleRatedAs.PASSENGER;
        userUpdateFieldPrefix = 'averageRatingAsPassenger';
        userUpdateCountField = 'totalRatingsAsPassenger';
        alreadyRatedField = 'driverRated';
        if (booking.driverRated) {
          ErrorHelper.ConflictException(
            'You have already rated the passenger for this booking.',
          );
        }
      } else {
        ErrorHelper.ForbiddenException(
          'You were not part of this booking and cannot rate it.',
        );
      }

      // 2. Check for existing rating (redundant due to unique index, but good practice)
      const existingRating = await this.ratingModel
        .findOne({ rater: raterId, booking: dto.bookingId })
        .session(session);
      if (existingRating) {
        ErrorHelper.ConflictException(
          'You have already submitted a rating for this booking.',
        );
      }

      // 3. Create and Save the Rating
      const newRating = new this.ratingModel({
        rater: raterId,
        ratee: rateeId,
        ride: booking.ride,
        booking: dto.bookingId,
        roleRatedAs: roleRatedAs,
        score: dto.score,
        comment: dto.comment,
      });
      await newRating.save({ session });
      this.logger.log(
        `Rating ${newRating._id} created by ${raterId} for ${rateeId} (booking ${dto.bookingId})`,
      );

      // 4. Update the User's Average Rating (Synchronous for now)
      const rateeUser = await this.userModel.findById(rateeId).session(session);
      if (!rateeUser) {
        // This should ideally not happen if refs are correct
        ErrorHelper.InternalServerErrorException(
          `User being rated (ID: ${rateeId}) not found.`,
        );
      }

      const currentTotalScore =
        (rateeUser[userUpdateFieldPrefix] || 0) *
        (rateeUser[userUpdateCountField] || 0);
      const newTotalRatings = (rateeUser[userUpdateCountField] || 0) + 1;
      const newAverageRating =
        (currentTotalScore + dto.score) / newTotalRatings;

      await this.userModel.updateOne(
        { _id: rateeId },
        {
          $set: { [userUpdateFieldPrefix]: newAverageRating },
          $inc: { [userUpdateCountField]: 1 },
        },
        { session },
      );
      this.logger.log(`Updated average rating for user ${rateeId}`);

      // 5. Mark rating as done on the booking
      await this.bookingModel.updateOne(
        { _id: dto.bookingId },
        { $set: { [alreadyRatedField]: true } },
        { session },
      );

      await session.commitTransaction();
      return newRating;
    } catch (error) {
      await session.abortTransaction();
      this.logger.error(
        `Error submitting rating for booking ${dto.bookingId} by user ${raterId}: ${error.message}`,
        error.stack,
      );
      if (error instanceof HttpException) throw error;
      // Handle potential unique constraint violation on rating
      if (
        error.code === 11000 &&
        error.message.includes('duplicate key error') &&
        error.message.includes('ratings')
      ) {
        ErrorHelper.ConflictException(
          'You have already submitted a rating for this booking.',
        );
      }
      ErrorHelper.InternalServerErrorException('Failed to submit rating.');
    } finally {
      session.endSession();
    }
  }
}
