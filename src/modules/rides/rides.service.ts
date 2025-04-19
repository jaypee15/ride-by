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

@Injectable()
export class RidesService {
  private readonly logger = new Logger(RidesService.name);

  constructor(
    @InjectModel(Ride.name) private rideModel: Model<RideDocument>,
    @InjectModel(Vehicle.name) private vehicleModel: Model<VehicleDocument>,
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    // Inject GeolocationService later
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
      departureTime: departureDateTime, // Use the Date object
      pricePerSeat: dto.pricePerSeat,
      initialSeats: vehicle.seatsAvailable, // Seats from verified vehicle
      availableSeats: vehicle.seatsAvailable, // Initially same as vehicle
      status: RideStatus.SCHEDULED,
      preferences: dto.preferences || [],
      // estimateArrivalTime: // TODO: Calculate using GeolocationService
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
      order,
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
        .sort({ departureTime: order === 'ASC' ? 1 : -1 }) // Sort by departure time
        .skip(skip)
        .limit(limit);

      const [results, totalCount] = await Promise.all([
        query.exec(),
        this.rideModel.countDocuments(conditions), // Get total count matching conditions
      ]);

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
}
