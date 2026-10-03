import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import mongoose, { Model } from 'mongoose';
import { Ride, RideDocument } from './schemas/ride.schema';
import { Vehicle, VehicleDocument } from '../driver/schemas/vehicle.schema';
import { User, UserDocument } from '../user/schemas/user.schema';
import { CreateRideDto } from './dto/create-ride.dto';
import { RoleNameEnum } from '../../core/interfaces/user/role.interface';
import { RideStatus } from './enums/ride-status.enum';
import { ErrorHelper } from 'src/core/helpers';
import { VehicleVerificationStatus } from 'src/core/enums/vehicle.enum';
import { DriverVerificationStatus, UserStatus } from 'src/core/enums/user.enum';
import { SearchRidesDto } from './dto/search-rides.dto';
import { PaginationResultDto } from 'src/core/dto';
import {
  GeolocationService,
  Coordinates,
} from '../geolocation/geolocation.service';
import { v4 as uuidv4 } from 'uuid'; // For generating unique tokens
import { InjectRedis } from '@nestjs-modules/ioredis'; // Assuming Redis for storing tokens
import Redis from 'ioredis';
import { Booking } from '../booking/schemas/booking.schema';
import { BookingStatus } from '../booking/enums/booking-status.enum';
import { PopulatedRideWithBookings } from './interfaces/populated-ride.interface';

@Injectable()
export class RidesService {
  private readonly logger = new Logger(RidesService.name);

  constructor(
    @InjectModel(Ride.name) private rideModel: Model<RideDocument>,
    @InjectModel(Vehicle.name) private vehicleModel: Model<VehicleDocument>,
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    @InjectModel(Booking.name) private bookingModel: Model<Booking>,
    @InjectRedis() private readonly redisClient: Redis,
    private readonly geolocationService: GeolocationService,
  ) {}

  async createRide(
    driverId: string,
    dto: CreateRideDto,
  ): Promise<RideDocument> {
    this.logger.log(`Attempting to create ride for driver ID: ${driverId}`);

    // 1. Validate Driver
    const driver = await this.userModel.findById(driverId).populate('roles');
    if (!driver) {
      ErrorHelper.NotFoundException('Driver user not found.');
    }
    const isDriverRole = driver.roles.some(
      (role) => role.name === RoleNameEnum.Driver,
    );
    if (!isDriverRole) {
      ErrorHelper.ForbiddenException('User is not registered as a driver.');
    }
    // Optional: Check driver status (e.g., must be ACTIVE and VERIFIED)

    if (
      driver.status !== UserStatus.ACTIVE ||
      driver.driverVerificationStatus !== DriverVerificationStatus.VERIFIED
    ) {
      ErrorHelper.ForbiddenException(
        'Driver account is not active or verified.',
      );
    }

    // 2. Validate Vehicle
    const vehicle = await this.vehicleModel.findById(dto.vehicleId);
    if (!vehicle) {
      ErrorHelper.NotFoundException(
        `Vehicle with ID ${dto.vehicleId} not found.`,
      );
    }
    if (vehicle.driver.toString() !== driverId) {
      ErrorHelper.ForbiddenException(
        'You cannot create a ride with a vehicle you do not own.',
      );
    }
    // Optional: Check vehicle verification status (strict check)
    if (
      vehicle.vehicleVerificationStatus !== VehicleVerificationStatus.VERIFIED
    ) {
      ErrorHelper.ForbiddenException(
        `Vehicle ${vehicle.plateNumber} is not verified.`,
      );
    }

    // 3. Validate Departure Time (must be in the future)
    const departureDateTime = new Date(dto.departureTime);
    if (isNaN(departureDateTime.getTime()) || departureDateTime <= new Date()) {
      ErrorHelper.BadRequestException(
        'Departure time must be a valid date in the future.',
      );
    }

    const originCoords: Coordinates = {
      lat: dto.origin.lat,
      lng: dto.origin.lon,
    };
    const destCoords: Coordinates = {
      lat: dto.destination.lat,
      lng: dto.destination.lon,
    };

    let estimatedArrivalTime: Date | undefined = undefined;
    try {
      const routeInfo = await this.geolocationService.calculateRoute(
        originCoords,
        destCoords,
      );
      if (routeInfo && routeInfo.durationSeconds > 0) {
        const departureDateTime = new Date(dto.departureTime);
        // Add duration (in seconds) to departure time
        estimatedArrivalTime = new Date(
          departureDateTime.getTime() + routeInfo.durationSeconds * 1000,
        );
        this.logger.log(
          `Estimated arrival time calculated: ${estimatedArrivalTime?.toISOString()}`,
        );
      } else {
        this.logger.warn(
          `Could not calculate route duration for ride creation by ${driverId}. Skipping arrival time estimation.`,
        );
      }
    } catch (geoError) {
      // Log the error but don't necessarily fail ride creation if route calc fails
      this.logger.warn(
        `Geolocation error during route calculation for ride creation by ${driverId}: ${geoError.message}`,
      );
    }

    // 4. Prepare Ride Data
    const rideData = {
      driver: driverId,
      vehicle: dto.vehicleId,
      origin: {
        type: 'Point' as const, // Ensure type is literal 'Point'
        coordinates: [dto.origin.lon, dto.origin.lat],
      },
      destination: {
        type: 'Point' as const,
        coordinates: [dto.destination.lon, dto.destination.lat],
      },
      originAddress: dto.originAddress,
      destinationAddress: dto.destinationAddress,
      departureTime: new Date(dto.departureTime), // Convert string to Date
      estimatedArrivalTime: estimatedArrivalTime, // Add calculated time
      pricePerSeat: dto.pricePerSeat,
      initialSeats: vehicle.seatsAvailable, // Seats from verified vehicle
      availableSeats: vehicle.seatsAvailable, // Initially same as vehicle
      status: RideStatus.SCHEDULED,
      preferences: dto.preferences || [],
      // waypoints: dto.waypoints?.map(wp => ({ type: 'Point', coordinates: [wp.lon, wp.lat] })) || [], // If waypoints are added
    };

    // 5. Create and Save Ride
    try {
      const newRide = new this.rideModel(rideData);
      await newRide.save();
      this.logger.log(
        `Ride ${newRide._id} created successfully by driver ${driverId}.`,
      );
      return newRide;
    } catch (error) {
      this.logger.error(
        `Error creating ride for driver ${driverId}: ${error.message}`,
        error.stack,
      );
      ErrorHelper.InternalServerErrorException('Failed to create ride.');
    }
  }

  async searchRides(
    dto: SearchRidesDto,
  ): Promise<PaginationResultDto<RideDocument>> {
    const {
      origin,
      //   destination,
      departureDate,
      seatsNeeded,
      maxDistance,
      limit,
      page,
    } = dto;
    const skip = dto.skip; // Use getter from PaginationDto

    // 1. Define Date Range for Departure
    // Search for rides on the specific date (from 00:00:00 to 23:59:59)
    const startOfDay = new Date(departureDate);
    startOfDay.setUTCHours(0, 0, 0, 0);

    const endOfDay = new Date(departureDate);
    endOfDay.setUTCHours(23, 59, 59, 999);

    // 2. Construct Query Conditions
    const conditions: mongoose.FilterQuery<RideDocument> = {
      status: RideStatus.SCHEDULED,
      availableSeats: { $gte: seatsNeeded },
      departureTime: {
        $gte: startOfDay,
        $lte: endOfDay,
      },
      // Geospatial query for origin
      origin: {
        $nearSphere: {
          $geometry: {
            type: 'Point',
            coordinates: [origin.lon, origin.lat],
          },
          $maxDistance: maxDistance, // Max distance in meters
        },
      },
      // We can filter destination after initial results or add another $nearSphere if performance allows
      // For simplicity, let's filter destination primarily after getting potential origins
    };

    // 3. Execute Query with Population and Pagination
    // NOTE: no .sort() here — $nearSphere already returns nearest-first and
    // Mongo rejects $near* combined with any other sort. The `order` query
    // param is still accepted for API compatibility but does not reorder
    // geo results.
    try {
      const query = this.rideModel
        .find(conditions)
        .populate<{ driver: UserDocument }>({
          // Populate driver with selected fields
          path: 'driver',
          select:
            'firstName lastName avatar averageRatingAsDriver totalRatingsAsDriver', // Only public fields
        })
        .populate<{ vehicle: VehicleDocument }>({
          // Populate vehicle with selected fields
          path: 'vehicle',
          select: 'make model year color features', // Only public fields
        })
        .skip(skip)
        .limit(limit);

      // countDocuments() rejects $near* predicates, so count via a lean
      // id-only find over the same conditions.
      const [results, idDocs] = await Promise.all([
        query.exec(),
        this.rideModel.find(conditions, { _id: 1 }).lean(),
      ]);
      const totalCount = idDocs.length;

      // Optional: Further filter by destination distance if needed (less efficient than DB query)
      // const filteredResults = results.filter(ride => { ... check destination distance ... });

      this.logger.log(
        `Found ${totalCount} rides matching criteria, returning page ${page}.`,
      );

      return new PaginationResultDto(results, totalCount, { page, limit });
    } catch (error) {
      this.logger.error(`Error searching rides: ${error.message}`, error.stack);
      ErrorHelper.InternalServerErrorException('Failed to search for rides.');
    }
  }

  // --- New getRideById method ---
  async getRideById(rideId: string): Promise<RideDocument> {
    if (!mongoose.Types.ObjectId.isValid(rideId)) {
      ErrorHelper.BadRequestException('Invalid Ride ID format.');
    }

    const ride = await this.rideModel
      .findById(rideId)
      .populate<{ driver: UserDocument }>({
        path: 'driver',
        select:
          'firstName lastName avatar averageRatingAsDriver totalRatingsAsDriver',
      })
      .populate<{ vehicle: VehicleDocument }>({
        path: 'vehicle',
        select: 'make model year color features plateNumber seatsAvailable', // Include plateNumber/seats for detail view
      })
      .exec();

    if (!ride) {
      ErrorHelper.NotFoundException(`Ride with ID ${rideId} not found.`);
    }

    return ride;
  }

  async startRide(driverId: string, rideId: string): Promise<RideDocument> {
    this.logger.log(`Driver ${driverId} attempting to start ride ${rideId}`);
    if (!mongoose.Types.ObjectId.isValid(rideId)) {
      ErrorHelper.BadRequestException('Invalid Ride ID format.');
    }

    // 1. Find Ride, verify driver and status
    const ride = await this.rideModel.findById(rideId);
    if (!ride) {
      ErrorHelper.NotFoundException(`Ride with ID ${rideId} not found.`);
    }
    if (ride.driver.toString() !== driverId) {
      ErrorHelper.ForbiddenException(
        'You can only start rides you are driving.',
      );
    }
    if (ride.status !== RideStatus.SCHEDULED) {
      ErrorHelper.BadRequestException(
        `Ride cannot be started (current status: ${ride.status}).`,
      );
    }

    // A ride may only start once at least one confirmed passenger is on it.
    // PENDING requests do not count: the driver has not accepted them yet, and
    // REJECTED / CANCELLED / NO_SHOW bookings must never hold a ride open.
    const confirmedPassengers = await this.bookingModel.countDocuments({
      ride: ride._id,
      status: BookingStatus.CONFIRMED,
    });
    if (confirmedPassengers < 1) {
      ErrorHelper.BadRequestException(
        `This ride needs at least 1 confirmed passenger to start (currently ${confirmedPassengers}).`,
      );
    }

    // Optional: Check if departure time is reasonably close

    // 2. Update Status
    ride.status = RideStatus.IN_PROGRESS;
    ride.startedAt = new Date();
    await ride.save();

    this.logger.log(
      `Ride ${rideId} started successfully by driver ${driverId}.`,
    );

    // TODO: Trigger Notification to confirmed Passengers (Phase 6)
    // await this.notificationService.notifyPassengersRideStarted(ride);

    return ride;
  }

  async generateShareLink(
    rideId: string,
    userId: string,
  ): Promise<{ shareToken: string; expiresAt: Date }> {
    this.logger.log(`User ${userId} requesting share link for ride ${rideId}`);
    // 1. Find Ride and verify status is IN_PROGRESS
    const ride = await this.rideModel
      .findById(rideId)
      .populate<PopulatedRideWithBookings>({
        path: 'bookings',
        select: 'passenger status',
      });

    if (!ride) ErrorHelper.NotFoundException(`Ride ${rideId} not found.`);
    if (ride.status !== RideStatus.IN_PROGRESS) {
      ErrorHelper.BadRequestException(
        'Can only share rides that are currently in progress.',
      );
    }

    // 2. Verify requesting user is the driver or a confirmed passenger
    const isDriver = ride.driver.toString() === userId;
    const isConfirmedPassenger = ride.bookings.some(
      (booking) =>
        booking.passenger.toString() === userId &&
        booking.status === BookingStatus.CONFIRMED,
    );

    if (!isDriver && !isConfirmedPassenger) {
      ErrorHelper.ForbiddenException(
        'You are not authorized to share this ride.',
      );
    }

    // 3. Generate unique token
    const shareToken = uuidv4(); // Simple unique token
    const expirySeconds = 4 * 60 * 60; // Example: 4 hours expiry
    const redisKey = `share_ride:${shareToken}`;
    const expiresAt = new Date(Date.now() + expirySeconds * 1000);

    // 4. Store token in Redis with Ride ID and expiry
    try {
      await this.redisClient.set(redisKey, rideId, 'EX', expirySeconds);
      this.logger.log(
        `Generated share token ${shareToken} for ride ${rideId}, expires in ${expirySeconds}s`,
      );
      return { shareToken, expiresAt };
    } catch (error) {
      this.logger.error(
        `Failed to store share token in Redis for ride ${rideId}: ${error.message}`,
        error.stack,
      );
      ErrorHelper.InternalServerErrorException(
        'Failed to generate share link.',
      );
    }
  }
  async getAllRidesByDriver(driverId: string): Promise<RideDocument[]> {
    this.logger.log(`Fetching all rides for driver: ${driverId}`);

    const driver = await this.userModel.findById(driverId).populate('roles');
    if (!driver) {
      ErrorHelper.NotFoundException('Driver not found.');
    }

    // const isDriverRole = driver.roles.some(
    //   (role) => role.name === RoleNameEnum.Driver,
    // );
    // if (!isDriverRole) {
    //   ErrorHelper.ForbiddenException('User is not a driver.');
    // }

    const rides = await this.rideModel
      .find({ driver: driverId })
      .populate<{ vehicle: VehicleDocument }>({
        path: 'vehicle',
        select: 'make model year color plateNumber seatsAvailable',
      })
      .sort({ departureTime: -1 })
      .exec();

    return rides;
  }
  async getAllRides(): Promise<RideDocument[]> {
    this.logger.log(`Fetching all rides`);

    const rides = await this.rideModel
      .find()
      .populate<{ vehicle: VehicleDocument }>({
        path: 'vehicle',
        select: 'make model year color plateNumber seatsAvailable',
      })
      .sort({ departureTime: -1 })
      .exec();

    return rides;
  }

  /**
   * Close a ride once nobody is still travelling on it.
   *
   * A ride holds many bookings, so "the trip is over" is a question about the
   * whole set, not one passenger. Only CONFIRMED bookings are considered live:
   * PENDING requests were never accepted, and COMPLETED / REJECTED / NO_SHOW /
   * CANCELLED_* have already left. The final CONFIRMED booking to be resolved
   * is what tips the ride into COMPLETED.
   *
   * SCHEDULED is settled too, not just IN_PROGRESS. Nothing forces a driver to
   * press Start before completing a booking, so a ride can reach this state
   * with every booking already delivered and the driver never having started
   * it. Leaving that ride in Upcoming forever would strand it there, and it
   * would also leave its passengers unable to close their own trip. With no
   * confirmed bookings left there is nobody riding, so COMPLETED is the honest
   * resting state -- nothing was cancelled, everyone was delivered.
   *
   * Idempotent and safe to call from anywhere -- if the ride is already
   * finished, or was cancelled, or other passengers are still riding, it simply
   * reports false and changes nothing.
   *
   * @returns true if this call is what moved the ride to COMPLETED.
   */
  async finalizeRideIfNoLiveBookings(rideId: string): Promise<boolean> {
    if (!mongoose.Types.ObjectId.isValid(rideId)) {
      ErrorHelper.BadRequestException('Invalid Ride ID format.');
    }

    const ride = await this.rideModel.findById(rideId);
    if (!ride) {
      ErrorHelper.NotFoundException(`Ride with ID ${rideId} not found.`);
    }

    // Nothing to finalize once the ride has already reached a resting state.
    if (
      ride.status !== RideStatus.IN_PROGRESS &&
      ride.status !== RideStatus.SCHEDULED
    ) {
      return false;
    }

    const liveBookings = await this.bookingModel.countDocuments({
      ride: ride._id,
      status: BookingStatus.CONFIRMED,
    });
    if (liveBookings > 0) {
      return false;
    }

    ride.status = RideStatus.COMPLETED;
    ride.completedAt = new Date();
    await ride.save();

    this.logger.log(
      `Ride ${rideId} auto-completed: no confirmed passengers remain.`,
    );
    // TODO: Trigger Notification to driver + remaining passengers (Phase 6)
    return true;
  }

  /**
   * Passenger closes out their own trip, from the driver's point of view the
   * trip is already over.
   *
   * The driver still owns the decision to call the delivery done -- this
   * endpoint deliberately refuses to run before that has happened, so a
   * passenger cannot end a ride that is still in progress just because they
   * feel like it. What the passenger is really doing is acknowledging the
   * finished trip, which is also what lets the ride itself be finalized.
   *
   * Scoped to the caller's own booking, never the ride wholesale: one passenger
   * tapping "End Ride" must not appear to close the trip for everybody else in
   * the car. The ride is only marked COMPLETED by
   * finalizeRideIfNoLiveBookings, and only once every booking has resolved.
   *
   * Idempotent by design. The client's End Ride button and this call are both
   * driven off "the driver confirmed delivery", so the booking is frequently
   * already COMPLETED by the time this arrives; a retry after a dropped
   * response must not look like an error.
   */
  async closeRideByPassenger(
    passengerId: string,
    rideId: string,
  ): Promise<RideDocument> {
    this.logger.log(
      `Passenger ${passengerId} attempting to close ride ${rideId}.`,
    );
    if (!mongoose.Types.ObjectId.isValid(rideId)) {
      ErrorHelper.BadRequestException('Invalid Ride ID format.');
    }

    const ride = await this.rideModel.findById(rideId);
    if (!ride) {
      ErrorHelper.NotFoundException(`Ride with ID ${rideId} not found.`);
    }

    // The caller's booking is what proves they were on this ride at all.
    const booking = await this.bookingModel.findOne({
      ride: ride._id,
      passenger: passengerId,
    });
    if (!booking) {
      ErrorHelper.ForbiddenException(
        'You can only close a ride you have a booking on.',
      );
    }

    // A cancelled ride is a dead end, not something to acknowledge.
    if (ride.status === RideStatus.CANCELLED) {
      ErrorHelper.ConflictException('This ride was cancelled.');
    }

    // The driver gate. COMPLETED on the booking is only ever set by the
    // driver confirming delivery, so this is where "the trip is really over"
    // is decided, and it is the only hard precondition. PENDING means the
    // driver has not accepted yet; a cancelled or rejected booking means the
    // passenger is not on this trip to close.
    if (booking.status !== BookingStatus.COMPLETED) {
      ErrorHelper.ConflictException(
        `Your driver has not confirmed delivery yet (booking status: ${booking.status}).`,
      );
    }

    // The ride may already be COMPLETED, e.g. a retry after a dropped response.
    // That is success, not a conflict.
    if (ride.status !== RideStatus.COMPLETED) {
      const finalized = await this.finalizeRideIfNoLiveBookings(rideId);
      // Re-read so the caller always gets the persisted state, including when
      // finalization was a no-op because other passengers are still riding.
      const updated = await this.rideModel.findById(rideId);
      this.logger.log(
        finalized
          ? `Ride ${rideId} closed by passenger ${passengerId}.`
          : `Passenger ${passengerId} acknowledged trip on ride ${rideId}; ` +
            `ride stays ${updated?.status} while other passengers ride.`,
      );
      return updated as RideDocument;
    }

    return ride;
  }
}
