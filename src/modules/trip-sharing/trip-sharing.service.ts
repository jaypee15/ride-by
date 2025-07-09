import { Injectable, Logger } from '@nestjs/common';
import { InjectRedis } from '@nestjs-modules/ioredis';
import Redis from 'ioredis';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Ride, RideDocument } from '../rides/schemas/ride.schema';
import { UserDocument } from '../user/schemas/user.schema';
import { VehicleDocument } from '../driver/schemas/vehicle.schema';
import { ErrorHelper } from 'src/core/helpers';
import { RideStatus } from '../rides/enums/ride-status.enum';

@Injectable()
export class TripSharingService {
  private readonly logger = new Logger(TripSharingService.name);
  private readonly shareTokenPrefix = 'share_ride:';

  constructor(
    @InjectRedis() private readonly redisClient: Redis,
    @InjectModel(Ride.name) private rideModel: Model<RideDocument>,
  ) {}

  async getTripStatusByToken(token: string): Promise<object | null> {
    const redisKey = `${this.shareTokenPrefix}${token}`;
    let rideId: string | null = null;

    try {
      rideId = await this.redisClient.get(redisKey);
      if (!rideId) {
        this.logger.warn(`Share token ${token} not found or expired in Redis.`);
        return null;
      }
    } catch (error) {
      this.logger.error(
        `Redis error fetching share token ${token}: ${error.message}`,
        error.stack,
      );
      ErrorHelper.InternalServerErrorException(
        'Error retrieving trip information.',
      );
    }

    try {
      const ride = await this.rideModel
        .findById(rideId)
        .select(
          'status originAddress destinationAddress estimatedArrivalTime driver vehicle',
        ) // Select fields
        .populate<{ driver: UserDocument }>('driver', 'firstName avatar') // Limited driver info
        .populate<{ vehicle: VehicleDocument }>(
          'vehicle',
          'make model color plateNumber',
        ); // Limited vehicle info

      if (!ride || ride.status !== RideStatus.IN_PROGRESS) {
        // Only show in-progress rides publicly
        this.logger.warn(
          `Ride ${rideId} for token ${token} not found or not in progress.`,
        );
        // Optionally delete expired/invalid token from Redis
        // await this.redisClient.del(redisKey);
        return null;
      }

      // Construct the limited public data object
      const publicData = {
        status: ride.status,
        origin: ride.originAddress,
        destination: ride.destinationAddress,
        estimatedArrival: ride.estimatedArrivalTime,
        driver: {
          firstName: ride.driver?.firstName,
          avatar: ride.driver?.avatar,
        },
        vehicle: {
          make: ride.vehicle?.make,
          model: ride.vehicle?.model,
          color: ride.vehicle?.color,
          plateNumber: ride.vehicle?.plateNumber, // Decide if plate number is too sensitive
        },
        // TODO: Add current location if available (from Phase 6 tracking)
        // currentLocation: ride.currentLocation
      };

      return publicData;
    } catch (error) {
      this.logger.error(
        `Error fetching ride ${rideId} for share token ${token}: ${error.message}`,
        error.stack,
      );
      ErrorHelper.InternalServerErrorException(
        'Error retrieving trip details.',
      );
    }
  }
}
