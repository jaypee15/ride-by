import { Injectable, Logger, HttpException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import mongoose, { Model } from 'mongoose';
import { Booking, BookingDocument } from './schemas/booking.schema';
import { Ride, RideDocument } from '../rides/schemas/ride.schema';
import { User, UserDocument } from '../user/schemas/user.schema';
import { CreateBookingDto } from './dto/create-booking.dto';
import { BookingStatus } from './enums/booking-status.enum';
import { RideStatus } from '../rides/enums/ride-status.enum';
import { ErrorHelper } from 'src/core/helpers';
import { PaymentStatus } from './enums/payment-status.enum';
import { PaginationDto, PaginationResultDto } from 'src/core/dto';
// Import NotificationService later

@Injectable()
export class BookingService {
  private readonly logger = new Logger(BookingService.name);

  constructor(
    @InjectModel(Booking.name) private bookingModel: Model<BookingDocument>,
    @InjectModel(Ride.name) private rideModel: Model<RideDocument>,
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    // Inject NotificationService later
    // Inject PaymentService later
  ) {}

  async requestBooking(
    passengerId: string,
    dto: CreateBookingDto,
  ): Promise<BookingDocument> {
    this.logger.log(
      `Passenger ${passengerId} requesting booking for ride ${dto.rideId}`,
    );

    // 1. Validate Passenger Exists (although AuthGuard does this, good practice)
    const passenger = await this.userModel.findById(passengerId);
    if (!passenger) {
      ErrorHelper.NotFoundException('Passenger user not found.'); // Should not happen if AuthGuard is used
    }

    // 2. Validate Ride Exists and is Suitable
    const ride = await this.rideModel.findById(dto.rideId);
    if (!ride) {
      ErrorHelper.NotFoundException(`Ride with ID ${dto.rideId} not found.`);
    }
    if (ride.status !== RideStatus.SCHEDULED) {
      ErrorHelper.BadRequestException(
        'This ride is not available for booking (already started, completed, or cancelled).',
      );
    }
    if (ride.driver.toString() === passengerId) {
      ErrorHelper.BadRequestException(
        'You cannot book a ride you are driving.',
      );
    }
    if (ride.availableSeats < dto.seatsNeeded) {
      ErrorHelper.BadRequestException(
        `Not enough seats available. Only ${ride.availableSeats} left.`,
      );
    }

    // 3. Check if Passenger Already Booked This Ride
    const existingBooking = await this.bookingModel.findOne({
      passenger: passengerId,
      ride: dto.rideId,
      status: {
        $nin: [
          BookingStatus.CANCELLED_BY_DRIVER,
          BookingStatus.CANCELLED_BY_PASSENGER,
          BookingStatus.REJECTED,
        ],
      }, // Check active/pending bookings
    });
    if (existingBooking) {
      ErrorHelper.ConflictException(
        'You have already requested or booked this ride.',
      );
    }

    // 4. Prepare Booking Data
    const totalPrice = ride.pricePerSeat * dto.seatsNeeded;
    const bookingData = {
      passenger: passengerId,
      driver: ride.driver, // Store driver ID from ride
      ride: dto.rideId,
      seatsBooked: dto.seatsNeeded,
      totalPrice: totalPrice,
      status: BookingStatus.PENDING, // Initial status
      paymentStatus:
        totalPrice > 0 ? PaymentStatus.PENDING : PaymentStatus.NOT_REQUIRED, // Set payment status
      pickupAddress: dto.pickupAddress, // Optional proposed address
      dropoffAddress: dto.dropoffAddress,
    };

    // 5. Create and Save Booking
    try {
      const newBooking = new this.bookingModel(bookingData);
      await newBooking.save();
      this.logger.log(
        `Booking ${newBooking._id} created successfully for ride ${dto.rideId} by passenger ${passengerId}`,
      );

      // TODO: Trigger Notification to Driver (Phase 6)
      // await this.notificationService.notifyDriverOfBookingRequest(ride.driver, newBooking);

      return newBooking;
    } catch (error) {
      this.logger.error(
        `Error creating booking for ride ${dto.rideId}: ${error.message}`,
        error.stack,
      );
      ErrorHelper.InternalServerErrorException(
        'Failed to create booking request.',
      );
    }
  }

  // --- Methods for Driver and Passenger booking management will be added below ---
  async getRideBookings(
    driverId: string,
    rideId: string,
  ): Promise<BookingDocument[]> {
    this.logger.log(`Driver ${driverId} fetching bookings for ride ${rideId}`);
    if (!mongoose.Types.ObjectId.isValid(rideId)) {
      ErrorHelper.BadRequestException('Invalid Ride ID format.');
    }

    // Verify the ride exists and the user is the driver
    const ride = await this.rideModel.findById(rideId).select('driver'); // Select only driver field
    if (!ride) {
      ErrorHelper.NotFoundException(`Ride with ID ${rideId} not found.`);
    }
    if (ride.driver.toString() !== driverId) {
      ErrorHelper.ForbiddenException('You are not the driver of this ride.');
    }

    // Fetch bookings for this ride, populate passenger details
    const bookings = await this.bookingModel
      .find({ ride: rideId, driver: driverId })
      .populate<{ passenger: UserDocument }>({
        path: 'passenger',
        select: 'firstName lastName avatar phoneNumber', // Select needed passenger info
      })
      .sort({ createdAt: -1 }) // Sort by newest first
      .exec();

    return bookings;
  }

  async confirmBooking(
    driverId: string,
    bookingId: string,
  ): Promise<BookingDocument> {
    this.logger.log(
      `Driver ${driverId} attempting to confirm booking ${bookingId}`,
    );
    if (!mongoose.Types.ObjectId.isValid(bookingId)) {
      ErrorHelper.BadRequestException('Invalid Booking ID format.');
    }

    const session = await this.bookingModel.db.startSession(); // Start mongoose session for transaction
    session.startTransaction();

    try {
      // 1. Find Booking within session, verify driver and status
      const booking = await this.bookingModel
        .findById(bookingId)
        .session(session);
      if (!booking) {
        ErrorHelper.NotFoundException(
          `Booking with ID ${bookingId} not found.`,
        );
      }
      if (booking.driver.toString() !== driverId) {
        ErrorHelper.ForbiddenException(
          'You cannot confirm a booking for a ride you are not driving.',
        );
      }
      if (booking.status !== BookingStatus.PENDING) {
        ErrorHelper.BadRequestException(
          `Booking is not in PENDING state (current state: ${booking.status}).`,
        );
      }

      // 2. Find Ride within session, verify seats
      const ride = await this.rideModel.findById(booking.ride).session(session);
      if (!ride) {
        // Should not happen if booking exists, but good check
        ErrorHelper.NotFoundException(
          `Associated ride ${booking.ride} not found.`,
        );
      }
      if (ride.availableSeats < booking.seatsBooked) {
        ErrorHelper.BadRequestException(
          `Not enough seats available on the ride to confirm this booking (needed: ${booking.seatsBooked}, available: ${ride.availableSeats}).`,
        );
      }

      // 3. Update Ride: Decrease available seats (atomic operation within transaction)
      const rideUpdateResult = await this.rideModel.updateOne(
        { _id: ride._id, availableSeats: { $gte: booking.seatsBooked } }, // Ensure seats didn't change concurrently
        { $inc: { availableSeats: -booking.seatsBooked } },
        { session },
      );

      if (rideUpdateResult.modifiedCount === 0) {
        // This means the seats were likely taken by another concurrent confirmation
        ErrorHelper.ConflictException(
          'Seats became unavailable while confirming. Please refresh.',
        );
      }

      // 4. Update Booking Status
      booking.status = BookingStatus.CONFIRMED;
      // Optionally update pickup/dropoff if driver agrees/modifies them
      await booking.save({ session }); // Save booking changes within session

      // TODO: Trigger Payment Initiation (Phase 3)
      // if (booking.totalPrice > 0) {
      //      await this.paymentService.initializeTransactionForBooking(booking);
      // }

      // TODO: Trigger Notification to Passenger (Phase 6)
      // await this.notificationService.notifyPassengerBookingConfirmed(booking.passenger, booking);

      await session.commitTransaction(); // Commit transaction if all steps succeed
      this.logger.log(
        `Booking ${bookingId} confirmed successfully by driver ${driverId}.`,
      );
      return booking;
    } catch (error) {
      await session.abortTransaction(); // Rollback on any error
      this.logger.error(
        `Error confirming booking ${bookingId}: ${error.message}`,
        error.stack,
      );
      // Rethrow specific exceptions or a generic one
      if (error instanceof HttpException) throw error;
      ErrorHelper.InternalServerErrorException('Failed to confirm booking.');
    } finally {
      session.endSession(); // Always end the session
    }
  }

  async rejectBooking(
    driverId: string,
    bookingId: string,
  ): Promise<BookingDocument> {
    this.logger.log(
      `Driver ${driverId} attempting to reject booking ${bookingId}`,
    );
    if (!mongoose.Types.ObjectId.isValid(bookingId)) {
      ErrorHelper.BadRequestException('Invalid Booking ID format.');
    }

    const booking = await this.bookingModel.findById(bookingId);

    if (!booking) {
      ErrorHelper.NotFoundException(`Booking with ID ${bookingId} not found.`);
    }
    if (booking.driver.toString() !== driverId) {
      ErrorHelper.ForbiddenException(
        'You cannot reject a booking for a ride you are not driving.',
      );
    }
    if (booking.status !== BookingStatus.PENDING) {
      ErrorHelper.BadRequestException(
        `Booking is not in PENDING state (current state: ${booking.status}). Cannot reject.`,
      );
    }

    booking.status = BookingStatus.REJECTED; // Use REJECTED instead of CANCELLED_BY_DRIVER for clarity
    await booking.save();

    this.logger.log(
      `Booking ${bookingId} rejected successfully by driver ${driverId}.`,
    );

    // TODO: Trigger Notification to Passenger (Phase 6)
    // await this.notificationService.notifyPassengerBookingRejected(booking.passenger, booking);

    return booking;
  }

  async getMyBookings(
    passengerId: string,
    paginationDto: PaginationDto,
  ): Promise<PaginationResultDto<BookingDocument>> {
    this.logger.log(`Passenger ${passengerId} fetching their bookings.`);
    const { limit, page, order } = paginationDto;
    const skip = paginationDto.skip;

    const conditions = { passenger: passengerId };

    const query = this.bookingModel
      .find(conditions)
      .populate<{ driver: UserDocument }>({
        path: 'driver',
        select: 'firstName lastName avatar',
      })
      .populate<{ ride: RideDocument }>({
        path: 'ride',
        select:
          'originAddress destinationAddress departureTime status pricePerSeat', // Select key ride info
        populate: { path: 'vehicle', select: 'make model color' }, // Populate nested vehicle info
      })
      .sort({ createdAt: order === 'ASC' ? 1 : -1 })
      .skip(skip)
      .limit(limit);

    const [results, totalCount] = await Promise.all([
      query.exec(),
      this.bookingModel.countDocuments(conditions),
    ]);

    return new PaginationResultDto(results, totalCount, { page, limit });
  }

  async cancelBooking(
    passengerId: string,
    bookingId: string,
  ): Promise<BookingDocument> {
    this.logger.log(
      `Passenger ${passengerId} attempting to cancel booking ${bookingId}`,
    );
    if (!mongoose.Types.ObjectId.isValid(bookingId)) {
      ErrorHelper.BadRequestException('Invalid Booking ID format.');
    }

    const session = await this.bookingModel.db.startSession();
    session.startTransaction();

    try {
      // 1. Find booking, verify passenger owns it and check status
      const booking = await this.bookingModel
        .findById(bookingId)
        .session(session);
      if (!booking) {
        ErrorHelper.NotFoundException(
          `Booking with ID ${bookingId} not found.`,
        );
      }
      if (booking.passenger.toString() !== passengerId) {
        ErrorHelper.ForbiddenException(
          'You can only cancel your own bookings.',
        );
      }

      // Define cancellable statuses
      const cancellableStatuses = [
        BookingStatus.PENDING,
        BookingStatus.CONFIRMED,
      ];
      if (!cancellableStatuses.includes(booking.status)) {
        ErrorHelper.BadRequestException(
          `Cannot cancel booking with status ${booking.status}.`,
        );
      }

      const wasConfirmed = booking.status === BookingStatus.CONFIRMED;

      // 2. Update Booking Status
      booking.status = BookingStatus.CANCELLED_BY_PASSENGER;
      await booking.save({ session });

      // 3. If booking was confirmed, increment available seats on ride
      if (wasConfirmed) {
        const rideUpdateResult = await this.rideModel.updateOne(
          { _id: booking.ride },
          { $inc: { availableSeats: booking.seatsBooked } }, // Increment seats back
          { session },
        );
        // Log if ride wasn't found or not updated, but maybe don't fail the cancellation
        if (rideUpdateResult.modifiedCount === 0) {
          this.logger.warn(
            `Could not increment seats for ride ${booking.ride} during cancellation of booking ${bookingId}. Ride might be deleted or status changed.`,
          );
        } else {
          this.logger.log(
            `Incremented available seats for ride ${booking.ride} by ${booking.seatsBooked}.`,
          );
        }
      }

      // TODO: Handle Refunds if payment was made (Phase 3)
      // if (wasConfirmed && booking.paymentStatus === PaymentStatus.PAID) {
      //      await this.paymentService.processRefundForBooking(booking);
      // }

      // TODO: Trigger Notification to Driver (Phase 6)
      // await this.notificationService.notifyDriverBookingCancelled(booking.driver, booking);

      await session.commitTransaction();
      this.logger.log(
        `Booking ${bookingId} cancelled successfully by passenger ${passengerId}.`,
      );
      return booking;
    } catch (error) {
      await session.abortTransaction();
      this.logger.error(
        `Error cancelling booking ${bookingId}: ${error.message}`,
        error.stack,
      );
      if (error instanceof HttpException) throw error;
      ErrorHelper.InternalServerErrorException('Failed to cancel booking.');
    } finally {
      session.endSession();
    }
  }
}
