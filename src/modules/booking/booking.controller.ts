import {
  Controller,
  Post,
  Body,
  UseGuards,
  Logger,
  Get,
  Param,
  Patch,
  Query,
} from '@nestjs/common';
import { BookingService } from './booking.service';
import { CreateBookingDto } from './dto/create-booking.dto';
import { AuthGuard } from '../../core/guards/authenticate.guard';
import { User } from '../../core/decorators/user.decorator';
import { IUser } from '../../core/interfaces/user/user.interface';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiQuery,
} from '@nestjs/swagger';
import { Booking } from './schemas/booking.schema'; // For response type hint
import mongoose from 'mongoose';
import { ErrorHelper } from 'src/core/helpers';
import { PaginationDto, PaginationResultDto } from 'src/core/dto';

@ApiTags('Bookings')
@ApiBearerAuth()
@UseGuards(AuthGuard) // All booking actions require authentication
@Controller()
export class BookingController {
  private readonly logger = new Logger(BookingController.name);

  constructor(private readonly bookingService: BookingService) {}

  @Post()
  @ApiOperation({ summary: 'Request to book a ride (Passenger only)' })
  @ApiResponse({
    status: 201,
    description: 'Booking request submitted successfully.',
    type: Booking,
  })
  @ApiResponse({
    status: 400,
    description:
      'Bad Request - Invalid input, ride not bookable, not enough seats, etc.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 404,
    description: 'Not Found - Ride or Passenger not found.',
  })
  @ApiResponse({
    status: 409,
    description: 'Conflict - Passenger already booked this ride.',
  })
  async requestBooking(
    @User() passenger: IUser, // Get authenticated passenger
    @Body() createBookingDto: CreateBookingDto,
  ): Promise<{ message: string; data: Booking }> {
    this.logger.log(
      `Passenger ${passenger._id} requesting booking for ride ${createBookingDto.rideId}`,
    );
    const newBooking = await this.bookingService.requestBooking(
      passenger._id,
      createBookingDto,
    );
    return {
      message: 'Booking request submitted successfully.',
      data: newBooking.toObject() as Booking,
    };
  }

  @Get('/driver/rides/:rideId/bookings') // Prefix with /driver
  @ApiOperation({
    summary: 'Get booking requests for a specific ride (Driver only)',
  })
  @ApiResponse({
    status: 200,
    description: 'List of bookings for the ride.',
    type: [Booking],
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - User is not the driver of this ride.',
  })
  @ApiResponse({ status: 404, description: 'Not Found - Ride not found.' })
  async getRideBookings(
    @User() driver: IUser,
    @Param('rideId') rideId: string,
  ): Promise<{ message: string; data: Booking[] }> {
    if (!mongoose.Types.ObjectId.isValid(rideId)) {
      ErrorHelper.BadRequestException('Invalid Ride ID format.');
    }
    this.logger.log(
      `Driver ${driver._id} fetching bookings for ride ${rideId}`,
    );
    const bookings = await this.bookingService.getRideBookings(
      driver._id,
      rideId,
    );
    return {
      message: 'Bookings fetched successfully.',
      data: bookings.map((b) => b.toObject() as Booking), // Return plain objects
    };
  }

  @Patch('/driver/bookings/:bookingId/confirm') // Prefix with /driver
  @ApiOperation({ summary: 'Confirm a pending booking request (Driver only)' })
  @ApiResponse({
    status: 200,
    description: 'Booking confirmed successfully.',
    type: Booking,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Booking not pending or not enough seats.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - User is not the driver.',
  })
  @ApiResponse({
    status: 404,
    description: 'Not Found - Booking or Ride not found.',
  })
  @ApiResponse({
    status: 409,
    description: 'Conflict - Seats became unavailable.',
  })
  async confirmBooking(
    @User() driver: IUser,
    @Param('bookingId') bookingId: string,
  ): Promise<{ message: string; data: Booking }> {
    if (!mongoose.Types.ObjectId.isValid(bookingId)) {
      ErrorHelper.BadRequestException('Invalid Booking ID format.');
    }
    this.logger.log(`Driver ${driver._id} confirming booking ${bookingId}`);
    const confirmedBooking = await this.bookingService.confirmBooking(
      driver._id,
      bookingId,
    );
    return {
      message: 'Booking confirmed successfully.',
      data: confirmedBooking.toObject() as Booking,
    };
  }

  @Patch('/driver/bookings/:bookingId/reject') // Prefix with /driver
  @ApiOperation({ summary: 'Reject a pending booking request (Driver only)' })
  @ApiResponse({
    status: 200,
    description: 'Booking rejected successfully.',
    type: Booking,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Booking not pending.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - User is not the driver.',
  })
  @ApiResponse({ status: 404, description: 'Not Found - Booking not found.' })
  async rejectBooking(
    @User() driver: IUser,
    @Param('bookingId') bookingId: string,
  ): Promise<{ message: string; data: Booking }> {
    if (!mongoose.Types.ObjectId.isValid(bookingId)) {
      ErrorHelper.BadRequestException('Invalid Booking ID format.');
    }
    this.logger.log(`Driver ${driver._id} rejecting booking ${bookingId}`);
    const rejectedBooking = await this.bookingService.rejectBooking(
      driver._id,
      bookingId,
    );
    return {
      message: 'Booking rejected successfully.',
      data: rejectedBooking.toObject() as Booking,
    };
  }

  @Get('/passenger/bookings') // Prefix with /passenger
  @ApiOperation({ summary: 'Get bookings made by the logged-in passenger' })
  @ApiQuery({ name: 'page', type: Number, required: false, example: 1 })
  @ApiQuery({ name: 'limit', type: Number, required: false, example: 10 })
  @ApiQuery({
    name: 'order',
    enum: ['ASC', 'DESC'],
    required: false,
    example: 'DESC',
  })
  @ApiResponse({
    status: 200,
    description: 'List of passenger bookings.',
    type: PaginationResultDto<Booking>,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  async getMyBookings(
    @User() passenger: IUser,
    @Query() paginationDto: PaginationDto, // Accept pagination query params
  ): Promise<PaginationResultDto<Booking>> {
    // Return paginated result
    this.logger.log(`Passenger ${passenger._id} fetching their bookings`);
    return await this.bookingService.getMyBookings(
      passenger._id,
      paginationDto,
    );
    // TransformInterceptor handles formatting
  }

  @Patch('/passenger/bookings/:bookingId/cancel') // Prefix with /passenger
  @ApiOperation({ summary: 'Cancel a booking made by the logged-in passenger' })
  @ApiResponse({
    status: 200,
    description: 'Booking cancelled successfully.',
    type: Booking,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Booking cannot be cancelled.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Not the owner of the booking.',
  })
  @ApiResponse({ status: 404, description: 'Not Found - Booking not found.' })
  async cancelBooking(
    @User() passenger: IUser,
    @Param('bookingId') bookingId: string,
  ): Promise<{ message: string; data: Booking }> {
    if (!mongoose.Types.ObjectId.isValid(bookingId)) {
      ErrorHelper.BadRequestException('Invalid Booking ID format.');
    }
    this.logger.log(
      `Passenger ${passenger._id} cancelling booking ${bookingId}`,
    );
    const cancelledBooking = await this.bookingService.cancelBooking(
      passenger._id,
      bookingId,
    );
    return {
      message: 'Booking cancelled successfully.',
      data: cancelledBooking.toObject() as Booking,
    };
  }

  @Post('/passenger/bookings/:bookingId/pay') // Prefix with /passenger
  @ApiOperation({
    summary: 'Initiate payment for a confirmed booking (Passenger only)',
  })
  @ApiResponse({
    status: 200,
    description:
      'Payment initialized successfully. Returns Paystack authorization data.',
    schema: {
      properties: {
        authorization_url: { type: 'string' },
        access_code: { type: 'string' },
        reference: { type: 'string' },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Booking not confirmable or already paid.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Not the owner of the booking.',
  })
  @ApiResponse({ status: 404, description: 'Not Found - Booking not found.' })
  @ApiResponse({ status: 500, description: 'Payment service error.' })
  async initiateBookingPayment(
    @User() passenger: IUser,
    @Param('bookingId') bookingId: string,
  ): Promise<{ message: string; data: any }> {
    // Return structure matches TransformInterceptor
    if (!mongoose.Types.ObjectId.isValid(bookingId)) {
      ErrorHelper.BadRequestException('Invalid Booking ID format.');
    }
    this.logger.log(
      `Passenger ${passenger._id} initiating payment for booking ${bookingId}`,
    );
    const paymentData = await this.bookingService.initiateBookingPayment(
      passenger._id,
      bookingId,
    );
    return {
      message:
        'Payment initialized successfully. Redirect user to authorization URL.',
      data: paymentData, // Contains { authorization_url, reference, access_code }
    };
  }

  @Patch('/driver/bookings/:bookingId/complete') // Prefix with /driver
  @ApiOperation({ summary: 'Mark a booking as completed (Driver only)' })
  @ApiResponse({
    status: 200,
    description: 'Booking marked as completed.',
    type: Booking,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Booking not in a completable state.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({ status: 403, description: 'Forbidden - Not the driver.' })
  @ApiResponse({ status: 404, description: 'Not Found - Booking not found.' })
  async completeBooking(
    @User() driver: IUser,
    @Param('bookingId') bookingId: string,
  ): Promise<{ message: string; data: Booking }> {
    if (!mongoose.Types.ObjectId.isValid(bookingId)) {
      ErrorHelper.BadRequestException('Invalid Booking ID format.');
    }
    this.logger.log(`Driver ${driver._id} completing booking ${bookingId}`);
    const completedBooking = await this.bookingService.completeBookingByDriver(
      driver._id,
      bookingId,
    );
    return {
      message: 'Booking marked as completed.',
      data: completedBooking.toObject() as Booking,
    };
  }
}
