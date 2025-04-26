import { RideStatus } from '../rides/enums/ride-status.enum';
import { Logger, UseGuards } from '@nestjs/common';
import {
  OnGatewayConnection,
  OnGatewayDisconnect,
  WebSocketGateway,
  SubscribeMessage,
  MessageBody,
  ConnectedSocket,
  WsException,
  WebSocketServer,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { WsGuard } from '../../core/guards/ws.guard'; // Use the WS Guard
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Message, MessageDocument } from './schemas/message.schema';
import { IUser } from 'src/core/interfaces'; // Assuming IUser is defined
import {
  IsNotEmpty,
  IsLongitude,
  IsLatitude,
  IsMongoId,
} from 'class-validator';
import { RideDocument, Ride } from '../rides/schemas/ride.schema';

// DTO for location update
class LocationUpdateDto {
  @IsNotEmpty() @IsMongoId() rideId: string;
  @IsNotEmpty() @IsLatitude() lat: number;
  @IsNotEmpty() @IsLongitude() lon: number;
}

@WebSocketGateway({
  cors: { origin: '*' },
  // namespace: 'ride', // Optional: use a namespace
  // path: '/api/communication/socket' // Example different path
})
@UseGuards(WsGuard)
export class ChatGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer() server: Server; // Inject the server instance
  private logger = new Logger(ChatGateway.name);

  constructor(
    @InjectModel(Message.name) private messageModel: Model<MessageDocument>,
    @InjectModel(Ride.name) private rideModel: Model<RideDocument>, // Inject RideModel
  ) {}

  handleConnection(client: Socket) {
    // User is already authenticated and joined their room via AppGateway/WsGuard
    const user = client.data.user as IUser;
    if (user) {
      this.logger.log(`Ride client connected: ${client.id}, User: ${user._id}`);
    } else {
      this.logger.warn(`Ride client connected without user data: ${client.id}`);
      client.disconnect(true); // Disconnect if user data somehow missing
    }
  }

  handleDisconnect(client: Socket) {
    const user = client.data.user as IUser;
    this.logger.log(
      `Ride client disconnected: ${client.id}, User: ${user?._id || 'N/A'}`,
    );
  }

  @SubscribeMessage('updateLocation')
  async handleLocationUpdate(
    @MessageBody() data: LocationUpdateDto,
    @ConnectedSocket() client: Socket,
  ): Promise<{ success: boolean }> {
    const driver = client.data.user as IUser;
    if (!driver)
      throw new WsException('Authentication data missing on socket.');
    // TODO: Add validation pipe for WebSocket DTOs if not configured globally

    this.logger.debug(
      `Received 'updateLocation' from driver ${driver._id} for ride ${data.rideId}`,
    );

    try {
      // 1. Find Ride and verify driver and status
      const ride = await this.rideModel
        .findById(data.rideId)
        .select('driver status');
      if (!ride) {
        this.logger.warn(
          `Location update received for non-existent ride ${data.rideId}`,
        );
        throw new WsException('Ride not found.');
      }
      if (ride.driver.toString() !== driver._id) {
        this.logger.warn(
          `User ${driver._id} attempted to update location for ride ${data.rideId} they are not driving.`,
        );
        throw new WsException(
          'Not authorized to update location for this ride.',
        );
      }
      if (ride.status !== RideStatus.IN_PROGRESS) {
        this.logger.warn(
          `Location update received for ride ${data.rideId} not in progress (status: ${ride.status}).`,
        );
        // Decide whether to throw or just ignore
        throw new WsException('Ride is not currently in progress.');
      }

      // 2. Prepare location data
      const locationData = {
        type: 'Point' as const,
        coordinates: [data.lon, data.lat],
      };
      const updateTime = new Date();

      // 3. Update Ride Document (optional, could also store in Redis)
      await this.rideModel.updateOne(
        { _id: data.rideId },
        {
          $set: {
            currentLocation: locationData,
            lastLocationUpdate: updateTime,
          },
        },
      );
      this.logger.debug(`Updated ride ${data.rideId} location in DB.`);

      // 4. Broadcast location update to a room specific to the ride
      const rideRoom = `ride_${data.rideId}`;
      const payload = {
        rideId: data.rideId,
        lat: data.lat,
        lon: data.lon,
        timestamp: updateTime,
      };
      // Emit to all sockets in the room *except* the sender (the driver)
      client.to(rideRoom).emit('locationUpdate', payload);
      this.logger.debug(`Broadcasted location update to room ${rideRoom}`);

      return { success: true };
    } catch (error) {
      this.logger.error(
        `Error handling 'updateLocation' from ${driver._id} for ride ${data.rideId}: ${error.message}`,
        error.stack,
      );
      client.emit(
        'exception',
        `Failed to update location: ${error.message || 'Server error'}`,
      );
      return { success: false };
    }
  }

  // Passengers need to join the ride room when they view the ride or it starts
  @SubscribeMessage('joinRideRoom')
  handleJoinRoom(
    @MessageBody() data: { rideId: string },
    @ConnectedSocket() client: Socket,
  ): void {
    const user = client.data.user as IUser;
    if (!user || !data.rideId) return; // Ignore if no user or rideId

    // TODO: Add verification: Is this user actually part of this ride (driver or confirmed passenger)?
    // This requires fetching booking/ride data which might be heavy here.
    // Maybe do verification when ride starts or details are fetched via HTTP.

    const roomName = `ride_${data.rideId}`;
    client.join(roomName);
    this.logger.log(`User ${user._id} joined room ${roomName}`);
  }

  @SubscribeMessage('leaveRideRoom')
  handleLeaveRoom(
    @MessageBody() data: { rideId: string },
    @ConnectedSocket() client: Socket,
  ): void {
    const user = client.data.user as IUser;
    if (!user || !data.rideId) return;

    const roomName = `ride_${data.rideId}`;
    client.leave(roomName);
    this.logger.log(`User ${user._id} left room ${roomName}`);
  }
}
