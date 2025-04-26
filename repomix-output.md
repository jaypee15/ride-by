This file is a merged representation of the entire codebase, combined into a single document by Repomix.

# File Summary

## Purpose
This file contains a packed representation of the entire repository's contents.
It is designed to be easily consumable by AI systems for analysis, code review,
or other automated processes.

## File Format
The content is organized as follows:
1. This summary section
2. Repository information
3. Directory structure
4. Repository files (if enabled)
4. Multiple file entries, each consisting of:
  a. A header with the file path (## File: path/to/file)
  b. The full contents of the file in a code block

## Usage Guidelines
- This file should be treated as read-only. Any changes should be made to the
  original repository files, not this packed version.
- When processing this file, use the file path to distinguish
  between different files in the repository.
- Be aware that this file may contain sensitive information. Handle it with
  the same level of security as you would the original repository.

## Notes
- Some files may have been excluded based on .gitignore rules and Repomix's configuration
- Binary files are not included in this packed representation. Please refer to the Repository Structure section for a complete list of file paths, including binary files
- Files matching patterns in .gitignore are excluded
- Files matching default ignore patterns are excluded
- Files are sorted by Git change count (files with more changes are at the bottom)

## Additional Info

# Directory Structure
```
src/
  core/
    adpater/
      index.ts
      redis.adpater.ts
    constants/
      base.constant.ts
      index.ts
      messages.constant.ts
    decorators/
      index.ts
      roles.decorator.ts
      user.decorator.ts
    dto/
      index.ts
      page-meta.dto.ts
      page-options.dto.ts
      pagination.dto.ts
    enums/
      auth.enum.ts
      user.enum.ts
      vehicle.enum.ts
    filters/
      http-exception.filter.ts
      index.ts
    guards/
      authenticate.guard.ts
      index.ts
      role.guards.ts
      ws.guard.ts
    helpers/
      date.helper.ts
      ecrypt.helper.ts
      error.utils.ts
      index.ts
    interceptors/
      index.ts
      logger.interceptor.ts
      transform.interceptor.ts
    interfaces/
      http/
        http.interface.ts
        index.ts
      user/
        index.ts
        role.interface.ts
        user.interface.ts
      index.ts
    redis/
      redis-lock.service.ts
      redis.module.ts
    validators/
      index.ts
      IsMatchPattern.validator.ts
      validate.validator.ts
  global/
    secrets/
      module.ts
      service.ts
    user-session/
      module.ts
      service.ts
    utils/
      token.utils.ts
    global.module.ts
  modules/
    admin/
      dto/
        update-verification.dto.ts
      admin.controller.ts
      admin.module.ts
      admin.service.ts
    auth/
      dto/
        auth-response.dto.ts
        auth.dto.ts
        base-registeration.dto.ts
        index.ts
        send-phone-otp.dto.ts
        update-user.dto.ts
      auth.controller.ts
      auth.module.ts
      auth.service.ts
    booking/
      dto/
        create-booking.dto.ts
      enums/
        booking-status.enum.ts
        payment-status.enum.ts
      schemas/
        booking.schema.ts
      booking.controller.ts
      booking.module.ts
      booking.service.ts
    communication/
      dto/
        send-message.dto.ts
      schemas/
        message.schema.ts
      chat.gateway.ts
      communication.module.ts
      ride.gateway.ts
    config/
      config.module.ts
    database/
      database.module.ts
    driver/
      dto/
        driver-registration.dto.ts
        register-vehicle.dto.ts
      enums/
        vehicle-document-type.enum.ts
      schemas/
        vehicle.schema.ts
      driver.controller.ts
      driver.module.ts
      driver.service.ts
    geolocation/
      geolocation.module.ts
      geolocation.service.ts
    health/
      health.controller.ts
      health.module.ts
    mail/
      cron-job/
        email.processor.ts
      dto/
        index.ts
        mail.dto.ts
      enums/
        index.ts
        mail.enum.ts
      schema/
        email.schema.ts
      templates/
        confirmation.ejs
        credentials.ejs
        emailnotification.ejs
        marketing.ejs
        resetpassword.ejs
      mail.controller.ts
      mail.event.ts
      mail.module.ts
      mail.service.ts
    notification/
      notification.module.ts
      notification.service.ts
    passenger/
      dto/
        passenger.dto.ts
    payment/
      payment.module.ts
      payment.service.ts
      webhook.controller.ts
    rating/
      dto/
        submit-rating.dto.ts
      enums/
        role-rated-as.enum.ts
      schemas/
        rating.schema.ts
      rating.controller.ts
      rating.module.ts
      rating.service.ts
    rides/
      dto/
        coordinates.dto.ts
        create-ride.dto.ts
        search-rides.dto.ts
      enums/
        ride-status.enum.ts
      interfaces/
        populated-ride.interface.ts
      schemas/
        ride.schema.ts
      rides.controller.ts
      rides.module.ts
      rides.service.ts
    storage/
      constants/
        index.ts
        secret-key.ts
      decorators/
        index.ts
        inject-secret.ts
      interfaces/
        index.ts
        secret-key.interfaces.ts
      index.ts
      s3-bucket.module.ts
      s3-bucket.service.ts
    trip-sharing/
      trip-sharing.controller.ts
      trip-sharing.module.ts
      trip-sharing.service.ts
    twilio/
      twiio.module.ts
      twilio.service.ts
    user/
      dto/
        emergency-contact.dto.ts
        register-device.dto.ts
      schemas/
        action.schema.ts
        role.schema.ts
        token.schema.ts
        user.schema.ts
      user.controller.ts
      user.module.ts
      user.service.ts
    app.gateway.ts
    app.module.ts
    main.module.ts
  main.ts
test/
  app.e2e-spec.ts
  jest-e2e.json
.eslintrc.js
.gitignore
.prettierrc
instructions.md
nest-cli.json
package.json
README.md
tsconfig.build.json
tsconfig.json
```

# Files

## File: src/core/decorators/roles.decorator.ts
````typescript
import { SetMetadata } from '@nestjs/common';
import { RoleNameEnum } from '../interfaces/user/role.interface';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: RoleNameEnum[]) =>
  SetMetadata(ROLES_KEY, roles);
````

## File: src/core/guards/role.guards.ts
````typescript
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RoleNameEnum } from '../interfaces/user/role.interface';
import { IUser } from '../interfaces/user/user.interface';
import { ROLES_KEY } from '../decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<RoleNameEnum[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!requiredRoles || requiredRoles.length === 0) {
      // If no roles are specified, access is allowed by default (AuthGuard already ran)
      // Or you might want to deny access if no roles specified for extra security
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user as IUser; // Assumes user object attached by AuthGuard

    if (!user || !user.roles) {
      // This shouldn't happen if AuthGuard ran successfully, but good check
      throw new ForbiddenException('User role information is missing.');
    }

    // Check if the user has at least one of the required roles
    const hasRequiredRole = requiredRoles.some(
      (role) =>
        // IMPORTANT: Check how roles are stored on your user object.
        // If user.roles is an array of Role *objects* with a 'name' property:
        (user.roles as any[]).some((userRole) => userRole.name === role),
      // If user.roles is an array of *strings* (role names):
      // user.roles.includes(role)
    );

    if (!hasRequiredRole) {
      throw new ForbiddenException(
        `Access denied. Required roles: ${requiredRoles.join(', ')}`,
      );
    }

    return true;
  }
}
````

## File: src/modules/communication/ride.gateway.ts
````typescript
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
````

## File: src/modules/notification/notification.module.ts
````typescript
import { Module, Global } from '@nestjs/common';
import { NotificationService } from './notification.service';
import { SecretsModule } from 'src/global/secrets/module'; // Ensure secrets are available
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from '../user/schemas/user.schema';

@Global() // Make service available globally without importing module explicitly
@Module({
  imports: [
    SecretsModule,
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
  ],
  providers: [NotificationService],
  exports: [NotificationService],
})
export class NotificationModule {}
````

## File: src/modules/notification/notification.service.ts
````typescript
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import * as admin from 'firebase-admin';
import { SecretsService } from '../../global/secrets/service';
import * as fs from 'fs';
import * as path from 'path';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from '../user/schemas/user.schema';

@Injectable()
export class NotificationService implements OnModuleInit {
  private readonly logger = new Logger(NotificationService.name);
  private isFirebaseInitialized = false;

  constructor(
    @InjectModel(User.name) private userRepo: Model<User>,
    private secretsService: SecretsService,
  ) {}

  onModuleInit() {
    const { serviceAccountPath } = this.secretsService.firebase;
    if (!serviceAccountPath) {
      this.logger.error(
        'Firebase Service Account Path not found. Cannot initialize Firebase Admin.',
      );
      return;
    }

    try {
      // Resolve path relative to project root (adjust if needed)
      const absolutePath = path.resolve(process.cwd(), serviceAccountPath);

      if (!fs.existsSync(absolutePath)) {
        this.logger.error(
          `Firebase service account file not found at: ${absolutePath}`,
        );
        return;
      }

      const serviceAccount = JSON.parse(fs.readFileSync(absolutePath, 'utf8'));

      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
      });
      this.isFirebaseInitialized = true;
      this.logger.log('Firebase Admin initialized successfully.');
    } catch (error) {
      this.logger.error(
        `Failed to initialize Firebase Admin: ${error.message}`,
        error.stack,
      );
    }
  }

  private checkInitialized(): void {
    if (!this.isFirebaseInitialized) {
      this.logger.error('Firebase Admin SDK not initialized.');
      // Optionally throw an error, but might be better to log and fail silently
      // throw new InternalServerErrorException('Notification service is not available.');
    }
  }

  // Send to specific tokens
  async sendPushNotificationToTokens(
    deviceTokens: string[],
    title: string,
    body: string,
    data?: { [key: string]: string }, // Optional data payload
  ): Promise<boolean> {
    this.checkInitialized();
    if (!deviceTokens || deviceTokens.length === 0) {
      this.logger.warn('No device tokens provided for push notification.');
      return false;
    }

    const message: admin.messaging.MulticastMessage = {
      notification: { title, body },
      tokens: deviceTokens,
      data: data || {}, // Add custom data payload if provided
      android: {
        // Optional: Android specific config
        priority: 'high',
        notification: {
          sound: 'default',
          // channelId: 'your_channel_id' // Define notification channels on Android
        },
      },
      apns: {
        // Optional: Apple specific config
        payload: {
          aps: {
            sound: 'default',
            // badge: 1, // Example badge count
          },
        },
      },
    };

    try {
      this.logger.log(
        `Sending push notification to ${deviceTokens.length} tokens. Title: ${title}`,
      );
      const response = await admin.messaging().sendEachForMulticast(message);
      this.logger.log(
        `Successfully sent message to ${response.successCount} devices`,
      );
      if (response.failureCount > 0) {
        const failedTokens = [];
        response.responses.forEach((resp, idx) => {
          if (!resp.success) {
            failedTokens.push(deviceTokens[idx]);
            this.logger.error(
              `Failed to send to token ${deviceTokens[idx]}: ${resp.error}`,
            );
            // TODO: Handle failed tokens (e.g., remove from user's deviceTokens array)
          }
        });
        this.logger.warn(
          `Failed to send to ${response.failureCount} devices. Failed tokens: ${failedTokens.join(', ')}`,
        );
      }
      return response.successCount > 0; // Return true if at least one succeeded
    } catch (error) {
      this.logger.error(
        `Error sending push notification: ${error.message}`,
        error.stack,
      );
      return false;
    }
  }

  async sendNotificationToUser(
    userId: string,
    title: string,
    body: string,
    data?: { [key: string]: string },
  ) {
    const user = await this.userRepo.findById(userId).select('deviceTokens');
    if (user && user.deviceTokens && user.deviceTokens.length > 0) {
      await this.sendPushNotificationToTokens(
        user.deviceTokens,
        title,
        body,
        data,
      );
    } else {
      this.logger.warn(`User ${userId} not found or has no device tokens.`);
    }
  }
}
````

## File: src/modules/user/dto/register-device.dto.ts
````typescript
import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class RegisterDeviceDto {
  @ApiProperty({ description: 'FCM device registration token' })
  @IsString()
  @IsNotEmpty()
  deviceToken: string;
}
````

## File: src/core/constants/index.ts
````typescript
export * from './base.constant';
export * from './messages.constant';
````

## File: src/core/enums/user.enum.ts
````typescript
export enum UserGender {
  MALE = 'MALE',
  FEMALE = 'FEMALE',
}

export enum UserStatus {
  ACTIVE = 'ACTIVE', // Verified and active
  INACTIVE = 'INACTIVE', // Deactivated by user or admin
  PENDING_EMAIL_VERIFICATION = 'PENDING_EMAIL_VERIFICATION', // Registered but email not verified
  PENDING_DRIVER_VERIFICATION = 'PENDING_DRIVER_VERIFICATION', // Email verified, driver docs submitted, pending admin approval
  SUSPENDED = 'SUSPENDED', // Temporarily suspended by admin
  BANNED = 'BANNED', // Permanently banned by admin
}

export enum DriverVerificationStatus {
  NOT_SUBMITTED = 'NOT_SUBMITTED',
  PENDING = 'PENDING',
  VERIFIED = 'VERIFIED',
  REJECTED = 'REJECTED',
}
````

## File: src/core/enums/vehicle.enum.ts
````typescript
export enum VehicleVerificationStatus {
  NOT_SUBMITTED = 'NOT_SUBMITTED',
  PENDING = 'PENDING',
  VERIFIED = 'VERIFIED',
  REJECTED = 'REJECTED',
}
````

## File: src/core/filters/http-exception.filter.ts
````typescript
import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
} from '@nestjs/common';

type ExceptionResponse = {
  statusCode: number;
  message: string | string[];
  error: string;
};

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter<HttpException> {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse();

    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const exceptionResponse = exception.getResponse() as ExceptionResponse;

    const getMessage = () => {
      if (typeof exceptionResponse === 'string') {
        return exceptionResponse;
      }

      if (typeof exceptionResponse.message === 'string') {
        return exceptionResponse.message;
      }

      if (Array.isArray(exceptionResponse.message)) {
        return exceptionResponse.message[0];
      }

      return 'Internal Server Error';
    };

    response.status(status).json({
      success: false,
      statusCode: status,
      message: getMessage(),
    });
  }
}
````

## File: src/core/filters/index.ts
````typescript
export * from './http-exception.filter';
````

## File: src/core/guards/ws.guard.ts
````typescript
import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { WsException } from '@nestjs/websockets';
import { Socket } from 'socket.io';

import { AuthGuard } from './authenticate.guard';

@Injectable()
export class WsGuard implements CanActivate {
  constructor(private authGuard: AuthGuard) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const client: Socket = context.switchToWs().getClient();

    const authorization =
      client.handshake.auth.token || client.handshake.headers.authorization;

    if (!authorization) {
      throw new WsException('Authorization header is missing');
    }

    try {
      const user = await this.verifyAccessToken(authorization);

      client.data.user = user;

      return true;
    } catch (error) {
      throw new WsException(error.message);
    }
  }

  async verifyAccessToken(authorization: string) {
    return this.authGuard.verifyAccessToken(authorization);
  }
}
````

## File: src/core/helpers/date.helper.ts
````typescript
import { DateTime, DurationLike } from 'luxon';

export class DateHelper {
  static isAfter(date: Date, dateToCompare: Date): boolean {
    return (
      DateTime.fromJSDate(new Date(date)) >
      DateTime.fromJSDate(new Date(dateToCompare))
    );
  }

  static addToCurrent(duration: DurationLike): Date {
    const dt = DateTime.now();
    return dt.plus(duration).toJSDate();
  }

  static isAfterCurrent(date: Date): boolean {
    const d1 = DateTime.fromJSDate(date ?? new Date());
    const d2 = DateTime.now();
    return d2 > d1;
  }
}
````

## File: src/core/helpers/ecrypt.helper.ts
````typescript
import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class EncryptHelper {
  async hash(str: string, saltRounds = 10): Promise<string> {
    return await bcrypt.hash(str, saltRounds);
  }

  async compare(str: string, hash: string): Promise<boolean> {
    return bcrypt.compare(str, hash);
  }

  compareSync(str: string, hash: string): boolean {
    return bcrypt.compareSync(str, hash);
  }

  hashSync(str: string, saltRounds = 10): string {
    return bcrypt.hashSync(str, saltRounds);
  }
}
````

## File: src/core/helpers/error.utils.ts
````typescript
import { HttpException, HttpStatus } from '@nestjs/common';

export class ErrorHelper {
  static BadRequestException(msg: string | string[]) {
    throw new HttpException(msg, HttpStatus.BAD_REQUEST);
  }
  static UnauthorizedException(msg: string) {
    throw new HttpException(msg, HttpStatus.UNAUTHORIZED);
  }
  static NotFoundException(msg: string) {
    throw new HttpException(msg, HttpStatus.NOT_FOUND);
  }
  static ForbiddenException(msg: string) {
    throw new HttpException(msg, HttpStatus.FORBIDDEN);
  }
  static ConflictException(msg: string) {
    throw new HttpException(msg, HttpStatus.CONFLICT);
  }
  static InternalServerErrorException(msg: string) {
    throw new HttpException(msg, HttpStatus.INTERNAL_SERVER_ERROR);
  }
}
````

## File: src/core/interceptors/index.ts
````typescript
export * from './logger.interceptor';
export * from './transform.interceptor';
````

## File: src/core/interceptors/logger.interceptor.ts
````typescript
import {
  CallHandler,
  ExecutionContext,
  Injectable,
  Logger,
  NestInterceptor,
} from '@nestjs/common';
import { Request } from 'express';
import { Observable, tap } from 'rxjs';

@Injectable()
export class LoggerInterceptor implements NestInterceptor {
  intercept(
    context: ExecutionContext,
    next: CallHandler<unknown>,
  ): Observable<unknown> {
    const request = context.switchToHttp().getRequest<Request>();
    const { method, ip, url } = request;
    const timestamp = new Date().toISOString();

    return next
      .handle()
      .pipe(
        tap(() =>
          Logger.log(
            `info ${timestamp} ip: ${ip} method: ${method} url: ${url}`,
          ),
        ),
      );
  }
}
````

## File: src/core/interceptors/transform.interceptor.ts
````typescript
import {
  CallHandler,
  ExecutionContext,
  Injectable,
  Logger,
  NestInterceptor,
} from '@nestjs/common';
import { Request } from 'express';
import { finalize, map, Observable } from 'rxjs';
import { AppResponse } from '../interfaces';
import { PaginationResultDto } from '../dto';

@Injectable()
export class TransformInterceptor<T> implements NestInterceptor<T, unknown> {
  intercept(
    context: ExecutionContext,
    next: CallHandler<unknown>,
  ): Observable<unknown> {
    const request = context.switchToHttp().getRequest<Request>();
    const { method, ip, url } = request;
    const now = Date.now();
    const timestamp = new Date().toISOString();

    Logger.log(`info ${timestamp} ip: ${ip} method: ${method} url: ${url}`);

    return next.handle().pipe(
      map((response: AppResponse) => {
        if (response?.data instanceof PaginationResultDto) {
          return {
            success: true,
            data: response?.data['data'],
            message: response?.message,
            meta: response?.data['meta'],
          };
        }

        return {
          success: true,
          data: response?.data,
          message: response?.message,
        };
      }),
      finalize(() => {
        Logger.log(`Excution time... ${Date.now() - now}ms`);
      }),
    );
  }
}
````

## File: src/core/interfaces/http/http.interface.ts
````typescript
export type AppResponse = {
  data: object;
  success: boolean;
  message: string;
};

export enum RequestHeadersEnum {
  Authorization = 'authorization',
}

export enum RequestMethodEnum {
  Get = 'GET',
  Post = 'POST',
  Put = 'PUT',
  Patch = 'PATCH',
  Delete = 'DELETE',
}
````

## File: src/core/redis/redis-lock.service.ts
````typescript
import { Injectable } from '@nestjs/common';
import { InjectRedis } from '@nestjs-modules/ioredis';
import { Redis } from 'ioredis';

@Injectable()
export class RedisLock {
  constructor(@InjectRedis() private redis: Redis) {}

  async acquire(key: string, value: string, ttl = 30 * 60 * 1000) {
    const result = await this.redis.set(key, value, 'PX', ttl, 'NX');

    return result === 'OK';
  }

  async release(key: string, value: string) {
    const script = `
                if redis.call("get", KEYS[1]) == ARGV[1] then
                    return redis.call("del", KEYS[1])
                else
                    return 0
                end
            `;

    const result = await this.redis.eval(script, 1, key, value);

    return result === 1;
  }
}
````

## File: src/core/redis/redis.module.ts
````typescript
import {
  RedisModule as RedisCoreModule,
  RedisModuleOptions,
} from '@nestjs-modules/ioredis';
import { SecretsService } from 'src/global/secrets/service';

export class RedisModule {
  static forRoot(secretKey: keyof SecretsService) {
    return RedisCoreModule.forRootAsync({
      inject: [SecretsService],
      useFactory: (secretsService: SecretsService): RedisModuleOptions => {
        const config = secretsService[secretKey];
        return {
          type: 'single',
          url: `redis://${config.REDIS_USERNAME}:${config.REDIS_PASSWORD}@${config.REDIS_HOST}:${config.REDIS_PORT}`,
        };
      },
    });
  }
}
````

## File: src/core/validators/index.ts
````typescript
export * from './IsMatchPattern.validator';
export * from './validate.validator';
````

## File: src/core/validators/IsMatchPattern.validator.ts
````typescript
import { registerDecorator, ValidationOptions } from 'class-validator';

export function IsMatchPattern(
  pattern: string,
  validationOptions?: ValidationOptions,
) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return function (object: Record<string, any>, propertyName: string) {
    registerDecorator({
      name: 'isValidPattern',
      target: object.constructor,
      propertyName: propertyName,
      options: {
        message: `${propertyName} is invalid`,
        ...validationOptions,
      },
      validator: {
        validate(value: string) {
          return typeof value === 'string' && new RegExp(pattern).test(value);
        },
      },
    });
  };
}
````

## File: src/core/validators/validate.validator.ts
````typescript
import { validate, ValidationError } from 'class-validator';

type Class = { new (...args: unknown[]): unknown };

const getMessages = (error: ValidationError) => {
  return Object.values(error.constraints).join(', ');
};

const validateDto = async (dto: Class, data: object) => {
  const d = Object.assign(new dto(), data);

  const errors = await validate(d);

  if (errors.length === 0) return null;

  return errors.map(getMessages).join('\n');
};

export default validateDto;
````

## File: src/global/user-session/service.ts
````typescript
import { Injectable, Logger } from '@nestjs/common';
import { InjectRedis } from '@nestjs-modules/ioredis';
import Redis from 'ioredis';
import { IDriver, IPassenger } from 'src/core/interfaces';

@Injectable()
export class UserSessionService {
  private logger = new Logger(UserSessionService.name);
  constructor(@InjectRedis() private readonly redisClient: Redis) {}

  async create(
    payload: IDriver | IPassenger,
    data: {
      sessionId: string;
      rememberMe: boolean;
    },
  ) {
    const key = `session:${payload._id}`;

    const twoWeeksInSeconds = 1209600;
    await this.redisClient.set(
      key,
      JSON.stringify({
        sessionId: data.sessionId,
        rememberMe: data.rememberMe,
      }),
      'EX',
      twoWeeksInSeconds,
    );

    this.logger.log(`create: Session created for user ${payload._id}`);

    return payload._id;
  }

  async get(id: string | number): Promise<{
    sessionId: string;
    rememberMe: boolean;
  }> {
    const key = `session:${id}`;
    const session = await this.redisClient.get(key);

    if (!session) {
      this.logger.error(`get: Session not found`);
      return null;
    }

    try {
      return JSON.parse(session);
    } catch (error) {
      this.logger.error(`get: ${error.name} - ${error.message}`);
      await this.redisClient.del(key);
      return null;
    }
  }

  async checkSession(id: string | number): Promise<boolean> {
    const key = `session:${id}`;
    const exist = await this.redisClient.get(key);

    if (!exist) {
      return false;
    }

    let parsed = null;
    try {
      parsed = JSON.parse(exist);
    } catch (error) {
      return false;
    }

    if (!parsed.rememberMe) {
      // Delete session if remember me is false
      await this.redisClient.del(key);
      return false;
    }

    return true;
  }

  async delete(id: string): Promise<boolean> {
    const key = `session:${id}`;

    try {
      await this.redisClient.del(key);
    } catch (error) {
      return false;
    }

    return true;
  }
}
````

## File: src/global/utils/token.utils.ts
````typescript
import { Injectable, Logger } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import * as otpGenerator from 'otp-generator';

import { SecretsService } from '../secrets/service';
import { ErrorHelper } from 'src/core/helpers';
import { IDriver, IPassenger } from 'src/core/interfaces';

@Injectable()
export class TokenHelper {
  private logger = new Logger(TokenHelper.name);
  constructor(private secretService: SecretsService) {}

  generate(payload: IDriver | IPassenger): {
    accessToken: string;
    expires: number;
    refreshToken: string;
    sessionId: string;
  } {
    const { JWT_SECRET: secret } = this.secretService.jwtSecret;

    const sessionId = this.generateRandomString();

    const token = jwt.sign({ ...payload, sessionId }, secret, {
      expiresIn: '14d',
    });

    const refreshToken = jwt.sign(
      {
        userId: payload._id,
        userEmail: payload.email,
        isRefreshToken: true,
        sessionId,
      },
      secret,
      {
        expiresIn: '14d',
      },
    );

    const decoded = jwt.decode(token) as jwt.JwtPayload;
    return {
      accessToken: token,
      expires: decoded.exp,
      // expiresIn: decoded.iat,
      refreshToken,
      sessionId,
    };
  }

  verify<T>(token: string, opts?: jwt.VerifyOptions): T {
    try {
      const { JWT_SECRET: secret } = this.secretService.jwtSecret;

      const options: jwt.VerifyOptions = {
        ...opts,
        algorithms: ['HS256'],
      };
      const payload = jwt.verify(token, secret, options);
      return payload as T;
    } catch (error) {
      this.logger.log('err', error);
      if (error.name === 'TokenExpiredError')
        ErrorHelper.UnauthorizedException('Access token expired');
      if (error.name === 'JsonWebTokenError')
        ErrorHelper.UnauthorizedException('Access token not valid');
      throw error;
    }
  }

  generatePasswordResetToken(payload: any): string {
    const { JWT_SECRET: secret } = this.secretService.jwtSecret;

    return jwt.sign(
      {
        userId: payload._id,
        userEmail: payload.email,
        isPasswordResetToken: true,
      },
      secret,
      {
        expiresIn: '1h',
      },
    );
  }

  generateRandomString(size = 21): string {
    return otpGenerator.generate(size, {
      digits: true,
      lowerCaseAlphabets: true,
      upperCaseAlphabets: true,
      specialChars: false,
    });
  }
  generateRandomCoupon(size = 10): string {
    return otpGenerator.generate(size, {
      digits: true,
      lowerCaseAlphabets: false,
      upperCaseAlphabets: true,
      specialChars: false,
    });
  }

  generateRandomPassword(size = 21): string {
    const data = otpGenerator.generate(size, {
      digits: true,
      lowerCaseAlphabets: true,
      upperCaseAlphabets: true,
      specialChars: true,
    });

    return 'D$' + data;
  }

  generateRandomNumber(size = 6): string {
    return otpGenerator.generate(size, {
      digits: true,
      lowerCaseAlphabets: false,
      upperCaseAlphabets: false,
      specialChars: false,
    });
  }
}
````

## File: src/global/global.module.ts
````typescript
import { Global, Module } from '@nestjs/common';

import { SecretsModule } from './secrets/module';
import { UserSessionModule } from './user-session/module';
import { TokenHelper } from './utils/token.utils';

@Global()
@Module({
  imports: [SecretsModule, UserSessionModule],
  providers: [TokenHelper],
  exports: [SecretsModule, TokenHelper, UserSessionModule],
})
export class GlobalModule {}
````

## File: src/modules/admin/dto/update-verification.dto.ts
````typescript
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsEnum,
  IsNotEmpty,
  IsOptional,
  IsString,
  ValidateIf,
} from 'class-validator';
import { DriverVerificationStatus } from 'src/core/enums/user.enum';
import { VehicleVerificationStatus } from 'src/core/enums/vehicle.enum';

export class UpdateDriverVerificationDto {
  @ApiProperty({
    enum: [
      DriverVerificationStatus.VERIFIED,
      DriverVerificationStatus.REJECTED,
    ],
    description: 'New status for driver verification',
  })
  @IsEnum([
    DriverVerificationStatus.VERIFIED,
    DriverVerificationStatus.REJECTED,
  ]) // Admin can only Verify or Reject
  @IsNotEmpty()
  status: DriverVerificationStatus.VERIFIED | DriverVerificationStatus.REJECTED;

  @ApiPropertyOptional({
    description: 'Reason for rejection (required if status is REJECTED)',
  })
  @IsOptional()
  @ValidateIf((o) => o.status === DriverVerificationStatus.REJECTED) // Require reason only if rejecting
  @IsNotEmpty({ message: 'Rejection reason is required when rejecting.' })
  @IsString()
  reason?: string;
}

export class UpdateVehicleVerificationDto {
  @ApiProperty({
    enum: [
      VehicleVerificationStatus.VERIFIED,
      VehicleVerificationStatus.REJECTED,
    ],
    description: 'New status for vehicle verification',
  })
  @IsEnum([
    VehicleVerificationStatus.VERIFIED,
    VehicleVerificationStatus.REJECTED,
  ])
  @IsNotEmpty()
  status:
    | VehicleVerificationStatus.VERIFIED
    | VehicleVerificationStatus.REJECTED;

  @ApiPropertyOptional({
    description: 'Reason for rejection (required if status is REJECTED)',
  })
  @IsOptional()
  @ValidateIf((o) => o.status === VehicleVerificationStatus.REJECTED)
  @IsNotEmpty({ message: 'Rejection reason is required when rejecting.' })
  @IsString()
  reason?: string;
}
````

## File: src/modules/admin/admin.controller.ts
````typescript
import {
  Controller,
  Get,
  Patch,
  Param,
  Body,
  UseGuards,
  Logger,
} from '@nestjs/common';
import { AdminService } from './admin.service';
import { AuthGuard } from '../../core/guards/authenticate.guard'; // Standard AuthGuard
// import { RolesGuard } from '../../core/guards/roles.guard'; // Need a RolesGuard
// import { Roles } from '../../core/decorators/roles.decorator'; // Need a Roles decorator
import { User as CurrentUser } from '../../core/decorators/user.decorator'; // Decorator to get current user
import { IUser } from 'src/core/interfaces';
import {
  UpdateDriverVerificationDto,
  UpdateVehicleVerificationDto,
} from './dto/update-verification.dto';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiParam,
} from '@nestjs/swagger';
import { User } from '../user/schemas/user.schema'; // Import schemas for response types
import { Vehicle } from '../driver/schemas/vehicle.schema';
import mongoose from 'mongoose';
import { ErrorHelper } from 'src/core/helpers';

@ApiTags('Admin - Verifications')
@ApiBearerAuth()
// @Roles(RoleNameEnum.Admin) // Apply Roles decorator when RolesGuard is implemented
@UseGuards(AuthGuard) // Use AuthGuard first, then RolesGuard
@Controller('admin/verifications')
export class AdminController {
  private readonly logger = new Logger(AdminController.name);

  constructor(private readonly adminService: AdminService) {}

  @Get('drivers/pending')
  @ApiOperation({
    summary: 'Get list of drivers pending verification (Admin only)',
  })
  @ApiResponse({
    status: 200,
    description: 'List of pending driver verifications.',
    type: [User],
  }) // Type hint
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - User is not an Admin.',
  })
  async getPendingDrivers(): Promise<{ message: string; data: User[] }> {
    this.logger.log('Request received for pending driver verifications');
    const drivers = await this.adminService.getPendingDriverVerifications();
    return {
      message: 'Pending driver verifications fetched successfully.',
      data: drivers.map((d) => d.toObject() as User),
    };
  }

  @Get('vehicles/pending')
  @ApiOperation({
    summary: 'Get list of vehicles pending verification (Admin only)',
  })
  @ApiResponse({
    status: 200,
    description: 'List of pending vehicle verifications.',
    type: [Vehicle],
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - User is not an Admin.',
  })
  async getPendingVehicles(): Promise<{ message: string; data: Vehicle[] }> {
    this.logger.log('Request received for pending vehicle verifications');
    const vehicles = await this.adminService.getPendingVehicleVerifications();
    return {
      message: 'Pending vehicle verifications fetched successfully.',
      data: vehicles.map((v) => v.toObject() as Vehicle),
    };
  }

  @Patch('drivers/:userId/status')
  @ApiOperation({ summary: 'Update driver verification status (Admin only)' })
  @ApiParam({ name: 'userId', description: 'ID of the driver user to update' })
  @ApiResponse({
    status: 200,
    description: 'Driver verification status updated.',
    type: User,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid input or status transition.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - User is not an Admin.',
  })
  @ApiResponse({ status: 404, description: 'Not Found - User not found.' })
  async updateDriverStatus(
    @CurrentUser() admin: IUser,
    @Param('userId') userId: string,
    @Body() updateDto: UpdateDriverVerificationDto,
  ): Promise<{ message: string; data: User }> {
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      ErrorHelper.BadRequestException('Invalid User ID format.');
    }
    this.logger.log(`Admin ${admin._id} updating driver ${userId} status`);
    const updatedDriver =
      await this.adminService.updateDriverVerificationStatus(
        admin._id,
        userId,
        updateDto,
      );
    return {
      message: 'Driver verification status updated successfully.',
      data: updatedDriver.toObject() as User,
    };
  }

  @Patch('vehicles/:vehicleId/status')
  @ApiOperation({ summary: 'Update vehicle verification status (Admin only)' })
  @ApiParam({ name: 'vehicleId', description: 'ID of the vehicle to update' })
  @ApiResponse({
    status: 200,
    description: 'Vehicle verification status updated.',
    type: Vehicle,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid input or status transition.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - User is not an Admin.',
  })
  @ApiResponse({ status: 404, description: 'Not Found - Vehicle not found.' })
  async updateVehicleStatus(
    @CurrentUser() admin: IUser,
    @Param('vehicleId') vehicleId: string,
    @Body() updateDto: UpdateVehicleVerificationDto,
  ): Promise<{ message: string; data: Vehicle }> {
    if (!mongoose.Types.ObjectId.isValid(vehicleId)) {
      ErrorHelper.BadRequestException('Invalid Vehicle ID format.');
    }
    this.logger.log(`Admin ${admin._id} updating vehicle ${vehicleId} status`);
    const updatedVehicle =
      await this.adminService.updateVehicleVerificationStatus(
        admin._id,
        vehicleId,
        updateDto,
      );
    return {
      message: 'Vehicle verification status updated successfully.',
      data: updatedVehicle.toObject() as Vehicle,
    };
  }
}
````

## File: src/modules/admin/admin.module.ts
````typescript
import { Module } from '@nestjs/common';
import { AdminService } from './admin.service';
import { AdminController } from './admin.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from '../user/schemas/user.schema';
import { Vehicle, VehicleSchema } from '../driver/schemas/vehicle.schema';
// Import AuthModule if guards depend on it and it's not global

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: Vehicle.name, schema: VehicleSchema },
    ]),
    // AuthModule, // If needed for guards
  ],
  providers: [AdminService],
  controllers: [AdminController],
})
export class AdminModule {}
````

## File: src/modules/admin/admin.service.ts
````typescript
import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from '../user/schemas/user.schema';
import { Vehicle, VehicleDocument } from '../driver/schemas/vehicle.schema';
import { DriverVerificationStatus, UserStatus } from 'src/core/enums/user.enum';
import { VehicleVerificationStatus } from 'src/core/enums/vehicle.enum';
import {
  UpdateDriverVerificationDto,
  UpdateVehicleVerificationDto,
} from './dto/update-verification.dto';
import { ErrorHelper } from 'src/core/helpers';

@Injectable()
export class AdminService {
  private readonly logger = new Logger(AdminService.name);

  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    @InjectModel(Vehicle.name) private vehicleModel: Model<VehicleDocument>,
    // TODO: Inject NotificationService later
  ) {}

  // --- Get Pending Verifications ---

  async getPendingDriverVerifications(): Promise<UserDocument[]> {
    this.logger.log('Fetching pending driver verifications');
    // Find users who have the DRIVER role and status PENDING_DRIVER_VERIFICATION
    // Adjust query based on your exact status flow for document submission
    return this.userModel
      .find({
        // 'roles.name': RoleNameEnum.Driver, // This requires querying populated roles or storing role name directly
        driverVerificationStatus: DriverVerificationStatus.PENDING, // Assuming status is set to PENDING when docs are uploaded
      })
      .select(
        'firstName lastName email driverLicenseFrontImageUrl driverLicenseBackImageUrl createdAt',
      ) // Select relevant fields
      .exec();
  }

  async getPendingVehicleVerifications(): Promise<VehicleDocument[]> {
    this.logger.log('Fetching pending vehicle verifications');
    return this.vehicleModel
      .find({
        vehicleVerificationStatus: VehicleVerificationStatus.PENDING,
      })
      .populate<{ driver: UserDocument }>('driver', 'firstName lastName email') // Show driver info
      .select(
        'make model year plateNumber vehicleRegistrationImageUrl vehicleInsuranceImageUrl proofOfOwnershipImageUrl createdAt',
      ) // Select relevant fields
      .exec();
  }

  // --- Update Verification Statuses ---

  async updateDriverVerificationStatus(
    adminUserId: string,
    targetUserId: string,
    dto: UpdateDriverVerificationDto,
  ): Promise<UserDocument> {
    this.logger.log(
      `Admin ${adminUserId} updating verification status for driver ${targetUserId} to ${dto.status}`,
    );

    const driver = await this.userModel.findById(targetUserId);
    if (!driver) {
      ErrorHelper.NotFoundException(`User with ID ${targetUserId} not found.`);
    }
    // Add check: ensure target user actually IS a driver?

    // Allow update only if current status is PENDING (or maybe REJECTED for re-verification)
    const validPreviousStatuses = [
      DriverVerificationStatus.PENDING,
      DriverVerificationStatus.REJECTED,
    ];
    if (!validPreviousStatuses.includes(driver.driverVerificationStatus)) {
      ErrorHelper.BadRequestException(
        `Cannot update verification status from current state: ${driver.driverVerificationStatus}`,
      );
    }

    driver.driverVerificationStatus = dto.status;
    driver.driverRejectionReason =
      dto.status === DriverVerificationStatus.REJECTED ? dto.reason : undefined;

    // IMPORTANT: Update User's overall status if they are now fully verified
    if (
      dto.status === DriverVerificationStatus.VERIFIED &&
      driver.status === UserStatus.PENDING_DRIVER_VERIFICATION
    ) {
      driver.status = UserStatus.ACTIVE;
      this.logger.log(`Setting user ${targetUserId} status to ACTIVE.`);
    } else if (dto.status === DriverVerificationStatus.REJECTED) {
      // Optional: Change user status back if needed, e.g., to PENDING_DRIVER_VERIFICATION or keep as ACTIVE but rejected
      // driver.status = UserStatus.PENDING_DRIVER_VERIFICATION;
    }

    await driver.save();

    // TODO: Send notification to driver about status change (Phase 6)
    // await this.notificationService.notifyDriverVerificationUpdate(driver, dto.status, dto.reason);

    this.logger.log(
      `Successfully updated driver ${targetUserId} verification status to ${dto.status}`,
    );
    return driver;
  }

  async updateVehicleVerificationStatus(
    adminUserId: string,
    vehicleId: string,
    dto: UpdateVehicleVerificationDto,
  ): Promise<VehicleDocument> {
    this.logger.log(
      `Admin ${adminUserId} updating verification status for vehicle ${vehicleId} to ${dto.status}`,
    );

    const vehicle = await this.vehicleModel.findById(vehicleId);
    if (!vehicle) {
      ErrorHelper.NotFoundException(`Vehicle with ID ${vehicleId} not found.`);
    }

    const validPreviousStatuses = [
      VehicleVerificationStatus.PENDING,
      VehicleVerificationStatus.REJECTED,
    ];
    if (!validPreviousStatuses.includes(vehicle.vehicleVerificationStatus)) {
      ErrorHelper.BadRequestException(
        `Cannot update verification status from current state: ${vehicle.vehicleVerificationStatus}`,
      );
    }

    vehicle.vehicleVerificationStatus = dto.status;
    vehicle.vehicleRejectionReason =
      dto.status === VehicleVerificationStatus.REJECTED
        ? dto.reason
        : undefined;

    await vehicle.save();

    // TODO: Send notification to driver about status change (Phase 6)
    // await this.notificationService.notifyVehicleVerificationUpdate(vehicle.driver, vehicle, dto.status, dto.reason);

    this.logger.log(
      `Successfully updated vehicle ${vehicleId} verification status to ${dto.status}`,
    );
    return vehicle;
  }
}
````

## File: src/modules/auth/dto/auth-response.dto.ts
````typescript
import { ApiProperty } from '@nestjs/swagger';

export class BaseResponseDto<T> {
  @ApiProperty({ description: 'Response message' })
  message: string;

  @ApiProperty({ description: 'Response data' })
  data: T;
}

export class AuthUserResponseDto {
  @ApiProperty({ description: 'User ID' })
  _id: string;

  @ApiProperty({ description: 'Email address' })
  email: string;

  @ApiProperty({ description: 'First name' })
  firstName: string;

  @ApiProperty({ description: 'Last name' })
  lastName: string;

  @ApiProperty({ description: 'Profile avatar URL', required: false })
  avatar?: string;

  @ApiProperty({ description: 'About section', required: false })
  about?: string;

  @ApiProperty({ description: 'Country', required: false })
  country?: string;

  @ApiProperty({ description: 'Phone number', required: false })
  phoneNumber?: string;

  @ApiProperty({ description: 'Email confirmation status' })
  emailConfirm: boolean;

  @ApiProperty({ description: 'Account creation date' })
  createdAt: Date;

  @ApiProperty({ description: 'Last seen date' })
  lastSeen: Date;
}
````

## File: src/modules/auth/dto/send-phone-otp.dto.ts
````typescript
import { IsNotEmpty, IsPhoneNumber, IsString, Length } from 'class-validator';

export class SendPhoneOtpDto {
  @IsString()
  @IsNotEmpty()
  @IsPhoneNumber('NG', {
    message:
      'Please provide a valid Nigerian phone number in E.164 format (e.g., +23480...)',
  })
  phoneNumber: string; // Expecting E.164 format (e.g., +2348012345678)
}

export class VerifyPhoneOtpDto {
  @IsString()
  @IsNotEmpty()
  @IsPhoneNumber('NG', {
    message:
      'Please provide a valid Nigerian phone number in E.164 format (e.g., +23480...)',
  })
  phoneNumber: string; // Expecting E.164 format

  @IsString()
  @IsNotEmpty()
  @Length(6, 6, { message: 'OTP must be exactly 6 digits' }) // Assuming 6-digit OTP
  otp: string;
}
````

## File: src/modules/booking/dto/create-booking.dto.ts
````typescript
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsInt,
  IsMongoId,
  IsNotEmpty,
  IsOptional,
  IsString,
  Min,
} from 'class-validator';

export class CreateBookingDto {
  @ApiProperty({
    description: 'ID of the ride to book',
    example: '605c72ef4e79a3a3e8f2d3b4',
  })
  @IsMongoId()
  @IsNotEmpty()
  rideId: string;

  @ApiProperty({ description: 'Number of seats to book', example: 1 })
  @IsInt()
  @Min(1)
  @IsNotEmpty()
  seatsNeeded: number;

  @ApiPropertyOptional({
    description: 'Proposed or agreed pickup address/description',
    example: 'Meet at Mobil Gas Station, Ikeja',
  })
  @IsOptional()
  @IsString()
  pickupAddress?: string;

  @ApiPropertyOptional({
    description: 'Proposed or agreed dropoff address/description',
    example: 'UI Main Gate',
  })
  @IsOptional()
  @IsString()
  dropoffAddress?: string;
}
````

## File: src/modules/booking/enums/booking-status.enum.ts
````typescript
export enum BookingStatus {
  PENDING = 'PENDING', // Passenger requested, driver action needed
  CONFIRMED = 'CONFIRMED', // Driver accepted, awaiting payment/start
  CANCELLED_BY_PASSENGER = 'CANCELLED_BY_PASSENGER',
  CANCELLED_BY_DRIVER = 'CANCELLED_BY_DRIVER',
  COMPLETED = 'COMPLETED', // Ride finished for this booking
  REJECTED = 'REJECTED', // Driver declined the request
  NO_SHOW = 'NO_SHOW', // Passenger didn't show up (optional)
}
````

## File: src/modules/booking/enums/payment-status.enum.ts
````typescript
export enum PaymentStatus {
  PENDING = 'PENDING', // Awaiting payment initiation/completion
  PAID = 'PAID', // Payment successful
  FAILED = 'FAILED', // Payment attempt failed
  REFUNDED = 'REFUNDED', // Payment was refunded
  NOT_REQUIRED = 'NOT_REQUIRED', // For free rides or cash payment (if supported)
}
````

## File: src/modules/booking/schemas/booking.schema.ts
````typescript
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { User } from '../../user/schemas/user.schema';
import { Ride } from '../../rides/schemas/ride.schema';
import { BookingStatus } from '../enums/booking-status.enum';
import { PaymentStatus } from '../enums/payment-status.enum';

export type BookingDocument = Booking & Document;

@Schema({ timestamps: true, collection: 'bookings' })
export class Booking {
  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  })
  passenger: User;

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  })
  driver: User; // Denormalize for easier querying/access

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Ride',
    required: true,
    index: true,
  })
  ride: Ride;

  @Prop({ type: Number, required: true, min: 1 })
  seatsBooked: number;

  @Prop({ type: Number, required: true, min: 0 })
  totalPrice: number; // Calculated: pricePerSeat * seatsBooked

  @Prop({
    type: String,
    enum: BookingStatus,
    default: BookingStatus.PENDING,
    index: true,
  })
  status: BookingStatus;

  @Prop({ type: String, required: false }) // Can be finalized during confirmation
  pickupAddress?: string;

  @Prop({ type: String, required: false })
  dropoffAddress?: string;

  @Prop({ type: String, enum: PaymentStatus, default: PaymentStatus.PENDING })
  paymentStatus: PaymentStatus;

  @Prop({ type: String, index: true, sparse: true }) // Store payment gateway reference
  transactionRef?: string;

  // Optional fields for reviews/ratings
  @Prop({ type: Boolean, default: false })
  passengerRated: boolean;

  @Prop({ type: Boolean, default: false })
  driverRated: boolean;

  // createdAt, updatedAt handled by timestamps: true
}

export const BookingSchema = SchemaFactory.createForClass(Booking);

// Index for querying user's bookings
BookingSchema.index({ passenger: 1, createdAt: -1 });
BookingSchema.index({ driver: 1, ride: 1 });
````

## File: src/modules/communication/dto/send-message.dto.ts
````typescript
import { ApiProperty } from '@nestjs/swagger';
import {
  IsMongoId,
  IsNotEmpty,
  IsOptional,
  IsString,
  MaxLength,
} from 'class-validator';

export class SendMessageDto {
  @ApiProperty({
    description: 'ID of the recipient user',
    example: '605c72ef4e79a3a3e8f2d3b4',
  })
  @IsMongoId()
  @IsNotEmpty()
  receiverId: string;

  @ApiProperty({
    description: 'The text content of the message',
    maxLength: 1000,
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(1000)
  content: string;

  @ApiProperty({
    description: 'Optional ID of the booking this message relates to',
    example: '605c72ef4e79a3a3e8f2d3b5',
    required: false,
  })
  @IsOptional()
  @IsMongoId()
  bookingId?: string;
}
````

## File: src/modules/communication/schemas/message.schema.ts
````typescript
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { User } from '../../user/schemas/user.schema';
import { Booking } from '../../booking/schemas/booking.schema'; // Optional link to booking

export type MessageDocument = Message & Document;

@Schema({ timestamps: true, collection: 'messages' })
export class Message {
  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  })
  sender: User;

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  })
  receiver: User;

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Booking',
    required: false,
    index: true,
  })
  booking?: Booking; // Optional: Link message to a specific booking context

  @Prop({ type: String, required: true, trim: true, maxlength: 1000 })
  content: string;

  @Prop({ type: Date }) // Timestamp when the receiver read the message
  readAt?: Date;

  // createdAt, updatedAt handled by timestamps: true
}

export const MessageSchema = SchemaFactory.createForClass(Message);

// Index for fetching chat history between two users
MessageSchema.index({ sender: 1, receiver: 1, createdAt: -1 });
// Index for fetching messages related to a booking
MessageSchema.index({ booking: 1, createdAt: -1 });
````

## File: src/modules/communication/chat.gateway.ts
````typescript
import { Logger, UseGuards } from '@nestjs/common';
import {
  OnGatewayConnection,
  OnGatewayDisconnect,
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  MessageBody,
  ConnectedSocket,
  WsException,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { WsGuard } from '../../core/guards/ws.guard'; // Use the WS Guard
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Message, MessageDocument } from './schemas/message.schema';
import { SendMessageDto } from './dto/send-message.dto';
import { IUser } from 'src/core/interfaces'; // Assuming IUser is defined
import mongoose from 'mongoose';

// Use a different path or port if needed, ensure it doesn't conflict with AppGateway if kept separate
// Or integrate this logic into AppGateway
@WebSocketGateway({
  cors: { origin: '*' },
  // namespace: 'chat', // Optional: use a namespace
  // path: '/api/communication/socket' // Example different path
})
@UseGuards(WsGuard) // Apply guard to the whole gateway (or individual handlers)
export class ChatGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer() server: Server; // Inject the server instance
  private logger = new Logger(ChatGateway.name);

  constructor(
    @InjectModel(Message.name) private messageModel: Model<MessageDocument>,
  ) {}

  // Handle connection/disconnection if needed specifically for chat
  handleConnection(client: Socket) {
    // User is already authenticated and joined their room via AppGateway/WsGuard
    const user = client.data.user as IUser;
    if (user) {
      this.logger.log(`Chat client connected: ${client.id}, User: ${user._id}`);
    } else {
      this.logger.warn(`Chat client connected without user data: ${client.id}`);
      client.disconnect(true); // Disconnect if user data somehow missing
    }
  }

  handleDisconnect(client: Socket) {
    const user = client.data.user as IUser;
    this.logger.log(
      `Chat client disconnected: ${client.id}, User: ${user?._id || 'N/A'}`,
    );
  }

  @SubscribeMessage('sendMessage')
  async handleMessage(
    @MessageBody() data: SendMessageDto,
    @ConnectedSocket() client: Socket,
  ): Promise<{ success: boolean; message?: MessageDocument }> {
    // Acknowledge message receipt
    const sender = client.data.user as IUser;
    if (!sender) {
      throw new WsException('Authentication data missing on socket.');
    }

    this.logger.log(
      `Received 'sendMessage' from ${sender._id} to ${data.receiverId}`,
    );

    try {
      // Basic validation (DTO validation happens via pipes if configured)
      if (!data.receiverId || !data.content) {
        throw new WsException('Missing receiverId or content.');
      }
      if (sender._id.toString() === data.receiverId) {
        throw new WsException('Cannot send message to yourself.');
      }

      // Save message to DB
      const newMessage = new this.messageModel({
        sender: sender._id,
        receiver: data.receiverId,
        content: data.content,
        booking: data.bookingId || undefined, // Link booking if provided
      });
      await newMessage.save();
      this.logger.log(
        `Message from ${sender._id} to ${data.receiverId} saved with ID ${newMessage._id}`,
      );

      // Emit message to the receiver's room (using their user ID as room name)
      this.server.to(data.receiverId).emit('newMessage', newMessage.toObject()); // Send plain object
      this.logger.log(`Emitted 'newMessage' to room ${data.receiverId}`);

      // Acknowledge success back to the sender
      return {
        success: true,
        message: newMessage.toObject() as MessageDocument,
      };
    } catch (error) {
      this.logger.error(
        `Error handling 'sendMessage' from ${sender._id}: ${error.message}`,
        error.stack,
      );
      // Send error back to the sender
      client.emit(
        'exception',
        `Failed to send message: ${error.message || 'Server error'}`,
      );
      return { success: false }; // Acknowledge failure
    }
  }

  // Optional: Handle message read status
  @SubscribeMessage('markAsRead')
  async handleMarkAsRead(
    @MessageBody() data: { messageId: string }, // Expect message ID
    @ConnectedSocket() client: Socket,
  ): Promise<{ success: boolean }> {
    const currentUser = client.data.user as IUser;
    if (!currentUser) {
      throw new WsException('Authentication data missing on socket.');
    }
    if (!data.messageId || !mongoose.Types.ObjectId.isValid(data.messageId)) {
      throw new WsException('Invalid messageId provided.');
    }

    try {
      const result = await this.messageModel.updateOne(
        { _id: data.messageId, receiver: currentUser._id, readAt: null }, // Find unread message for this user
        { $set: { readAt: new Date() } },
      );
      if (result.modifiedCount > 0) {
        this.logger.log(
          `Message ${data.messageId} marked as read by user ${currentUser._id}`,
        );
        // Optional: notify sender that message was read?
        return { success: true };
      } else {
        this.logger.log(
          `Message ${data.messageId} not found, not receiver, or already read by ${currentUser._id}`,
        );
        return { success: false }; // No update happened
      }
    } catch (error) {
      this.logger.error(
        `Error marking message ${data.messageId} as read: ${error.message}`,
        error.stack,
      );
      client.emit(
        'exception',
        `Failed to mark message as read: ${error.message || 'Server error'}`,
      );
      return { success: false };
    }
  }
}
````

## File: src/modules/communication/communication.module.ts
````typescript
import { Module } from '@nestjs/common';
import { ChatGateway } from './chat.gateway';
import { MongooseModule } from '@nestjs/mongoose';
import { Message, MessageSchema } from './schemas/message.schema';
import { AppModule } from '../app.module';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Message.name, schema: MessageSchema }]),
    AppModule,
  ],
  providers: [ChatGateway], // Add ChatGateway
  exports: [ChatGateway], // Export if needed
})
export class CommunicationModule {}
````

## File: src/modules/config/config.module.ts
````typescript
import { Module } from '@nestjs/common';

@Module({})
export class ConfigModule {}
````

## File: src/modules/database/database.module.ts
````typescript
import { Module } from '@nestjs/common';

@Module({})
export class DatabaseModule {}
````

## File: src/modules/driver/dto/driver-registration.dto.ts
````typescript
import { BaseRegistrationDto } from 'src/modules/auth/dto/base-registeration.dto';

// For the initial user creation, driver-specific details like license and vehicle info
// are usually collected *after* the account is created during an onboarding/verification flow.
// Therefore, this DTO extends the base without additional required fields for registration itself.

export class DriverRegistrationDto extends BaseRegistrationDto {}
````

## File: src/modules/driver/dto/register-vehicle.dto.ts
````typescript
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsArray,
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  Min,
  Max,
  MinLength,
  MaxLength,
  IsUppercase, // For plate number potentially
  ArrayMaxSize,
} from 'class-validator';

export class RegisterVehicleDto {
  @ApiProperty({ example: 'Toyota', description: 'Make of the vehicle' })
  @IsString()
  @IsNotEmpty()
  @MinLength(2)
  @MaxLength(50)
  make: string;

  @ApiProperty({ example: 'Camry', description: 'Model of the vehicle' })
  @IsString()
  @IsNotEmpty()
  @MinLength(1)
  @MaxLength(50)
  model: string;

  @ApiProperty({ example: 2018, description: 'Year of manufacture' })
  @IsInt()
  @Min(1980) // Adjust range as needed
  @Max(new Date().getFullYear()) // Cannot be newer than current year
  year: number;

  @ApiProperty({ example: 'Blue', description: 'Color of the vehicle' })
  @IsString()
  @IsNotEmpty()
  @MaxLength(30)
  color: string;

  @ApiProperty({
    example: 'ABC123XY',
    description: 'Vehicle plate number (unique)',
  })
  @IsString()
  @IsNotEmpty()
  @IsUppercase() // Optional: Enforce uppercase if desired
  @MaxLength(15) // Adjust max length
  plateNumber: string;

  @ApiProperty({
    example: 4,
    description: 'Number of seats available for passengers (excluding driver)',
  })
  @IsInt()
  @Min(1)
  @Max(10) // Set a reasonable max
  seatsAvailable: number;

  @ApiPropertyOptional({
    type: [String],
    example: ['Air Conditioning', 'USB Port'],
    description: 'List of vehicle features/amenities',
  })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  @ArrayMaxSize(10) // Limit number of features
  features?: string[];
}
````

## File: src/modules/driver/enums/vehicle-document-type.enum.ts
````typescript
export enum VehicleDocumentType {
  REGISTRATION = 'REGISTRATION',
  INSURANCE = 'INSURANCE',
  PROOF_OF_OWNERSHIP = 'PROOF_OF_OWNERSHIP',
  VEHICLE_PERMIT = 'VEHICLE_PERMIT',
  ROADWORTHINESS = 'ROADWORTHINESS',
}
````

## File: src/modules/driver/driver.module.ts
````typescript
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
````

## File: src/modules/geolocation/geolocation.service.ts
````typescript
import {
  Injectable,
  Logger,
  InternalServerErrorException,
  BadRequestException,
} from '@nestjs/common';
// Keep enum imports for other parts like TravelMode
import {
  Client,
  DirectionsRequest,
  GeocodeRequest,
  ReverseGeocodeRequest,
  LatLngLiteral,
  TravelMode,
} from '@googlemaps/google-maps-services-js';
import { SecretsService } from '../../global/secrets/service';
import { ErrorHelper } from 'src/core/helpers';

// Interfaces remain the same
export interface Coordinates {
  lat: number;
  lng: number;
}
export interface AddressComponents {
  streetNumber?: string;
  route?: string;
  locality?: string;
  administrativeAreaLevel1?: string;
  country?: string;
  postalCode?: string;
  formattedAddress?: string;
}
export interface RouteInfo {
  distanceMeters: number;
  durationSeconds: number;
}

@Injectable()
export class GeolocationService {
  private readonly logger = new Logger(GeolocationService.name);
  private googleMapsClient: Client | null = null;

  constructor(private secretsService: SecretsService) {
    const { apiKey } = this.secretsService.googleMaps;
    if (apiKey) {
      this.googleMapsClient = new Client({});
    } else {
      this.logger.error(
        'Google Maps API Key not found. GeolocationService will not function.',
      );
    }
  }

  private checkClient(): void {
    if (!this.googleMapsClient) {
      this.logger.error(
        'Google Maps client not initialized due to missing API key.',
      );
      throw new InternalServerErrorException(
        'Geolocation service is not configured properly.',
      );
    }
  }

  async geocode(address: string): Promise<Coordinates | null> {
    this.checkClient();
    const params: GeocodeRequest['params'] = {
      address: address,
      key: this.secretsService.googleMaps.apiKey,
      components: 'country:NG',
    };

    try {
      this.logger.log(`Geocoding address: ${address}`);
      const response = await this.googleMapsClient.geocode({ params });

      if (response.data.status === 'OK' && response.data.results.length > 0) {
        const location = response.data.results[0].geometry.location;
        this.logger.log(
          `Geocode successful for "${address}": ${JSON.stringify(location)}`,
        );
        return location;
      } else {
        this.logger.warn(
          `Geocoding failed for address "${address}". Status: ${response.data.status}, Error: ${response.data.error_message}`,
        );
        if (response.data.status === 'ZERO_RESULTS') {
          throw new BadRequestException(
            `Could not find coordinates for the address: ${address}`,
          );
        }
        throw new InternalServerErrorException(
          `Geocoding failed with status: ${response.data.status}`,
        );
      }
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof InternalServerErrorException
      ) {
        throw error;
      }
      this.logger.error(
        `Error calling Google Geocoding API for address "${address}": ${error.message}`,
        error.stack,
      );
      ErrorHelper.InternalServerErrorException('Failed to perform geocoding.');
    }
  }

  async reverseGeocode(
    lat: number,
    lng: number,
  ): Promise<AddressComponents | null> {
    this.checkClient();
    const params: ReverseGeocodeRequest['params'] = {
      latlng: { lat, lng },
      key: this.secretsService.googleMaps.apiKey,
    };

    try {
      this.logger.log(`Reverse geocoding coordinates: lat=${lat}, lng=${lng}`);
      const response = await this.googleMapsClient.reverseGeocode({ params });

      if (response.data.status === 'OK' && response.data.results.length > 0) {
        const firstResult = response.data.results[0];
        const components: AddressComponents = {
          formattedAddress: firstResult.formatted_address,
        };

        // Cast component.types to string[] before using .includes with string literals
        firstResult.address_components.forEach((component) => {
          const types = component.types as string[]; // Cast here
          if (types.includes('street_number'))
            components.streetNumber = component.long_name;
          if (types.includes('route')) components.route = component.long_name;
          if (types.includes('locality'))
            components.locality = component.long_name;
          if (types.includes('administrative_area_level_1'))
            components.administrativeAreaLevel1 = component.long_name;
          if (types.includes('country'))
            components.country = component.long_name;
          if (types.includes('postal_code'))
            components.postalCode = component.long_name;
        });

        this.logger.log(
          `Reverse geocode successful for ${lat},${lng}: "${components.formattedAddress}"`,
        );
        return components;
      } else {
        this.logger.warn(
          `Reverse geocoding failed for ${lat},${lng}. Status: ${response.data.status}, Error: ${response.data.error_message}`,
        );
        return null;
      }
    } catch (error) {
      this.logger.error(
        `Error calling Google Reverse Geocoding API for ${lat},${lng}: ${error.message}`,
        error.stack,
      );
      ErrorHelper.InternalServerErrorException(
        'Failed to perform reverse geocoding.',
      );
    }
    return null;
  }

  async calculateRoute(
    origin: LatLngLiteral,
    destination: LatLngLiteral,
    waypoints?: LatLngLiteral[],
  ): Promise<RouteInfo | null> {
    this.checkClient();
    const params: DirectionsRequest['params'] = {
      origin: origin,
      destination: destination,
      waypoints: waypoints,
      key: this.secretsService.googleMaps.apiKey,
      mode: TravelMode.driving, // Enum is correct here
    };

    try {
      this.logger.log(
        `Calculating route from ${JSON.stringify(origin)} to ${JSON.stringify(destination)}`,
      );
      const response = await this.googleMapsClient.directions({ params });

      if (response.data.status === 'OK' && response.data.routes.length > 0) {
        const route = response.data.routes[0];
        if (route.legs.length > 0) {
          let totalDistance = 0;
          let totalDuration = 0;
          route.legs.forEach((leg) => {
            totalDistance += leg.distance?.value || 0;
            totalDuration += leg.duration?.value || 0;
          });

          this.logger.log(
            `Route calculation successful: Distance=${totalDistance}m, Duration=${totalDuration}s`,
          );
          return {
            distanceMeters: totalDistance,
            durationSeconds: totalDuration,
          };
        }
      }

      this.logger.warn(
        `Route calculation failed. Status: ${response.data.status}, Error: ${response.data.error_message}`,
      );
      if (response.data.status === 'ZERO_RESULTS') {
        throw new BadRequestException(
          'Could not find a driving route between the specified locations.',
        );
      }
      return null;
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      this.logger.error(
        `Error calling Google Directions API: ${error.message}`,
        error.stack,
      );
      ErrorHelper.InternalServerErrorException('Failed to calculate route.');
    }
    return null;
  }
}
````

## File: src/modules/health/health.module.ts
````typescript
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TerminusModule } from '@nestjs/terminus';

import { HealthController } from './health.controller';

@Module({
  imports: [TerminusModule, ConfigModule],
  controllers: [HealthController],
})
export class HealthModule {}
````

## File: src/modules/mail/cron-job/email.processor.ts
````typescript
import { Processor, Process } from '@nestjs/bull';
import { Job } from 'bull';
import { Injectable, Logger } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import * as ejs from 'ejs';
import * as fs from 'fs';
import * as path from 'path';

@Processor('emailQueue')
@Injectable()
export class EmailProcessor {
  private logger = new Logger(EmailProcessor.name);

  constructor(private mailerService: MailerService) {}

  private from = '"TravEazi Team" <notifications@travezi.com>';

  // Resolve the path and read the template file
  private marketingTemplatePath = path.resolve(
    __dirname,
    '..',
    'templates',
    'marketing.ejs',
  );

  private marketingEmailTemplate = fs.readFileSync(this.marketingTemplatePath, {
    encoding: 'utf-8',
  });

  @Process('sendBulkEmail')
  async handleBulkEmailJob(job: Job) {
    const data = job.data;
    const batchSize = 50; // Number of emails per batch
    const maxRetries = 3; // Maximum number of retries
    const batches = [];

    for (let i = 0; i < data.to.length; i += batchSize) {
      batches.push(data.to.slice(i, i + batchSize));
    }

    this.logger.log(`Scheduled time for job ${job.id}: ${data.sendTime}`);

    for (const batch of batches) {
      const emailPromises = batch.map((recipient) => {
        let retries = 0;
        const sendEmail = async () => {
          try {
            return await this.mailerService.sendMail({
              to: recipient.email,
              from: this.from,
              subject: data.subject,
              context: {
                name: recipient.firstName,
                email: data.email,
                body: data.body,
              },
              headers: {
                'X-Category': data.type,
              },
              html: ejs.render(this.marketingEmailTemplate, {
                subject: data.subject,
                name: recipient.firstName,
                body: data.body,
              }),
              text: ejs.render(this.marketingEmailTemplate, {
                subject: data.subject,
                name: recipient.firstName,
                body: data.body,
              }),
            });
          } catch (error) {
            if (retries < maxRetries) {
              retries++;
              this.logger.warn(
                `Retry ${retries} for email to ${recipient.email}`,
              );
              await new Promise((resolve) => setTimeout(resolve, 1000)); // Wait for 1 second before retrying
              return sendEmail();
            } else {
              throw error;
            }
          }
        };
        return sendEmail();
      });

      try {
        const results = await Promise.all(emailPromises);
        this.logger.log(`Batch sent successfully: ${results}`);
      } catch (error) {
        this.logger.error(`Failed to send batch: ${error.message}`);
        throw error;
      }

      await new Promise((resolve) => setTimeout(resolve, 1000)); // Wait for 1 second before sending the next batch
    }

    await job.update({ status: 'completed' });
    return { status: 'completed', jobId: job.id };
  }
}
````

## File: src/modules/mail/dto/index.ts
````typescript
export * from './mail.dto';
````

## File: src/modules/mail/dto/mail.dto.ts
````typescript
import {
  IsArray,
  IsBoolean,
  IsEnum,
  IsNumber,
  IsObject,
  IsOptional,
  IsString,
} from 'class-validator';
import { MailType } from '../enums/mail.enum';
import { envType } from 'src/core/interfaces';
import { PaginationDto } from 'src/core/dto';

export class SendMailDto {
  @IsArray()
  @IsOptional()
  to?: string[];

  @IsString()
  @IsOptional()
  body?: string;

  @IsString()
  @IsOptional()
  cc?: string;

  @IsString()
  subject: string;

  @IsEnum(MailType)
  type: MailType;

  @IsObject()
  data: object & { env?: envType };

  @IsBoolean()
  saveAsNotification: boolean;
}

export class GetScheduleEmailsDto extends PaginationDto {
  @IsNumber()
  @IsOptional()
  limit: number;

  @IsNumber()
  @IsOptional()
  page: number;
}
````

## File: src/modules/mail/schema/email.schema.ts
````typescript
import { Schema, SchemaFactory, Prop } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({
  timestamps: true,
})
export class Email extends Document {
  @Prop({ type: String })
  event: string;

  @Prop({ type: String })
  event_id: string;

  @Prop({ type: String })
  email: string;

  @Prop({ type: String, required: false })
  ip: string;

  @Prop({ type: String, required: false })
  user_agent: string;

  @Prop({ type: String, required: false })
  url: string;

  @Prop({ type: String, required: false })
  response: string;

  @Prop({ type: String, required: false })
  response_code: string;

  @Prop({ type: String, required: false })
  bounce_category: string;

  @Prop({ type: String, required: false })
  reason: string;

  @Prop({ type: String })
  timestamp: string;

  @Prop({ type: String })
  sending_stream: string;

  @Prop({ type: String })
  category: string;

  @Prop({ type: { variable_a: String, variable_b: String }, required: false })
  custom_variables?: { variable_a: String; variable_b: String };

  @Prop({ type: String })
  message_id: string;
}

export const EmailSchema = SchemaFactory.createForClass(Email);
````

## File: src/modules/mail/templates/confirmation.ejs
````
<!doctype html>
<html>
  <meta charset="utf-8" />
  <title>Email Verification | TravEazi</title>

  <head>
    <link
      href="https://fonts.googleapis.com/css2?family=DM+Sans&family=Inter:wght@100;200;300;400;600&family=Joan&family=Roboto:ital,wght@0,100;0,300;1,100&display=swap"
      rel="stylesheet"
    />
    <style>
      * {
        font-family: 'DM Sans', sans-serif;
        color: #000000;
        font-weight: 400;
        font-size: 14px;
        line-height: 24px;
        text-align: justify;
      }

      body {
        background: #f0f7ff;
        -webkit-font-smoothing: antialiased;
        font-size: 14px;
        line-height: 1.4;
        margin: 1.5rem;
        display: flex;
        justify-content: center;
        padding: 1rem;
        -ms-text-size-adjust: 100%;
        -webkit-text-size-adjust: 100%;
      }

      .main {
        padding: 2rem;
        width: auto;
        background: white;
        margin: 1.5rem;
        border-radius: 8px;
        box-shadow: 0px 10px 30px rgba(0, 0, 0, 0.01);
      }

      .container {
        padding: 24px;
        max-width: 600px;
        background: #eef2f5;
        border-radius: 10px;
      }

      p {
        font-size: 14px;
      }

      a {
        color: #000;
        text-decoration: none;
      }

      footer {
        margin-top: 2rem;
      }

      footer div,
      footer aside {
        display: flex;
        justify-content: space-between;
        align-items: center;
        width: 100%;
        text-align: center;
        gap: 8px;
      }

      footer div {
        width: 30%;
        margin: 16px auto;
      }

      .main-header {
        font-style: normal;
        font-weight: 700;
        font-size: 20px;
        margin-bottom: 10px;
      }

      .user-name {
        font-style: normal;
        font-size: 16px;
      }

      .fw-bold {
        font-weight: 600;
        text-decoration: none;
      }

      .bold {
        font-style: bold;
        font-size: 30px;
      }

      .center-text {
        width: 100%;
        margin: auto;
        text-align: center;
      }

      .mt-n5 {
        margin-top: -5px;
      }

      .my-50 {
        margin: 15px 0px;
        text-align: center;
      }

      main aside {
        margin-top: 16px;
        font-size: 14px;
      }

      .landmark {
        color: #616161;
        margin-bottom: 16px;
        margin: auto;
        width: 100%;
        text-align: center;
      }

      .image {
        display: block;
        width: 80px;
        margin: auto;
        object-fit: contain;
        pointer-events: none;
      }

      .logo {
        height: 30px;
        width: 30px;
        margin: auto;
      }

      img.g-img + div {
        display: none;
      }

      .content {
        padding: 0 10px;
      }

      table {
        margin: 20px 5px;
      }

      .bg-bg {
        background: #eef2f5;
        padding: 20px 10px;
        width: 30%;
        margin: 10px auto;
      }

      .bg-dark {
        color: #000;
        font-weight: 700;
      }
    </style>
  </head>

  <body>
    <div class="container">
        <div class="main-header">
            <img
            class="logo"
            src="https://trav-eazi.s3.amazonaws.com/logo.png"
            alt="TravEazi Logo"
            />
            <h1 class="mt-n5">TravEazi</h1>
      <div class="main">
        <table role="presentation" cellpadding="2px" class="content">
          <p class="user-name">Hi <%= locals.name %>,</p>
          <p>
            Thank you for signing up to TravEazi! Please enter the One-Time Password (OTP) below
             to complete your registration,
            :
          </p>
          <h2 class="my-50 fw-bold bg-bg center-text bold">
            <%= locals.code %>
          </h2>
          <h5>
            This OTP is valid for the next 15 minutes. If you don't use it
            within this time frame, you will need to request a new one.
          </h5>
          <h5>
            If you did not initiate this request, please ignore this email.
          </h5>
          <p>Best regards,</p>
          <p>
            <a class="bg-dark" href="https://www.traveazi.com"
              >TravEazi Team</a
            >
          </p>
        </table>
      </div>
      <footer>
        
        <aside>
          <small class="landmark"
            >Copyright &copy; <%= new Date().getFullYear() %>
          </small>
        </aside>
        <p class="center-text fw-bold">TravEazi</p>
      </footer>
    </div>
  </body>
</html>
````

## File: src/modules/mail/templates/credentials.ejs
````
<!doctype html>
<html>
  <meta charset="utf-8" />
  <title>Welcome | xtern.ai</title>

  <head>
    <link
      href="https://fonts.googleapis.com/css2?family=DM+Sans&family=Inter:wght@100;200;300;400;600&family=Joan&family=Roboto:ital,wght@0,100;0,300;1,100&display=swap"
      rel="stylesheet"
    />
    <style>
      * {
        font-family: 'DM Sans', sans-serif;
        color: #000000;
        font-weight: 400;
        font-size: 14px;
        line-height: 24px;
        text-align: justify;
      }

      body {
        background: #f0f7ff;
        -webkit-font-smoothing: antialiased;
        font-size: 14px;
        line-height: 1.4;
        margin: 1.5rem;
        padding: 1rem;
        display: flex;
        justify-content: center;
        -ms-text-size-adjust: 100%;
        -webkit-text-size-adjust: 100%;
      }

      .main {
        padding: 2rem;
        width: auto;
        background: white;
        margin: 1.5rem;
        border-radius: 8px;
        box-shadow: 0px 10px 30px rgba(0, 0, 0, 0.01);
      }

      .container {
        padding: 24px;
        max-width: 600px;
        background: #eef2f5;
        border-radius: 10px;
      }

      p {
        font-size: 14px;
      }

      a {
        color: #000;
        text-decoration: none;
      }

      footer {
        margin-top: 2rem;
      }

      footer div,
      footer aside {
        display: flex;
        justify-content: space-between;
        align-items: center;
        width: 100%;
        text-align: center;
        gap: 8px;
      }

      footer div {
        width: 30%;
        margin: 16px auto;
      }

      .main-header {
        font-style: normal;
        font-weight: 700;
        font-size: 20px;
        margin-bottom: 10px;
      }

      .user-name {
        font-style: normal;
        font-size: 16px;
      }

      .fw-bold {
        font-weight: 600;
        text-decoration: none;
      }

      .bold {
        font-style: bold;
        font-size: 30px;
      }

      .center-text {
        width: 100%;
        margin: auto;
        text-align: center;
      }

      .mt-n5 {
        margin-top: -5px;
      }

      .my-50 {
        margin: 15px 0px;
        text-align: center;
      }

      main aside {
        margin-top: 16px;
        font-size: 14px;
      }

      .landmark {
        color: #616161;
        margin-bottom: 16px;
        margin: auto;
        width: 100%;
        text-align: center;
      }

      .image {
        display: block;
        width: 80px;
        margin: auto;
        object-fit: contain;
        pointer-events: none;
      }

      .logo {
        height: 30px;
        width: 30px;
        margin: auto;
      }

      img.g-img + div {
        display: none;
      }

      .content {
        padding: 0 40px;
      }

      table {
        margin: 20px 5px;
      }

      .bg-bg {
        background: #eef2f5;
        padding: 20px 10px;
        width: 80%;
        margin: 10px auto;
      }

      .bg-dark {
        color: #000;
        font-weight: 700;
      }
    </style>
  </head>

  <body>
    <div class="container">
      <a href="#">
        <img
          class="image g-img"
          src="https://traveazi-io-nonprod-general-revamp.s3.eu-west-2.amazonaws.com/1726625876998-xtern-logo.png"
          alt="traveazi.io logo"
        />
      </a>
      <div class="main">
        <table role="presentation" cellpadding="2px" class="content">
          <h3 class="main-header center-text">Welcome to Xtern.ai</h3>
          <p class="user-name">Hi <%= locals.name %>,</p>
          <p>
            We are delighted to inform you that your account has been
            successfully created on TravEazi.io. Please find the details of your
            account below:
          </p>
          <p>
            Email Address:
            <span class="fw-bold mt-n5"> <%= locals.email %> </span>
          </p>
          <div>
            Password:
            <p class="my-50 fw-bold bg-bg center-text bold">
              <%= locals.password %>
            </p>
          </div>
          <p>
            Kindly use the provided password to sign in to your TravEazi.io
            account. Once signed in, we <b>strongly recommend </b>changing your
            password for enhanced security.
          </p>
          <p>Thank you for choosing xtern.ai</p>
          <p>Best regards,</p>
          <p>
            <a class="bg-dark" href="https://www.traveazi.ai"
              >TravEazi Support Team</a
            >
          </p>
        </table>
      </div>
      <footer>
        <div>
          <span class="center-text">
            <a href="https://www.facebook.com/official.traveazi.io/">
              <img
                class="logo"
                src="https://traveazi-io-nonprod-general-revamp.s3.eu-west-2.amazonaws.com/1726627249979-facebook.png"
                alt="facebook logo"
              />
            </a>
          </span>
          <span class="center-text">
            <a href="https://www.linkedin.com/company/traveazi-io/">
              <img
                class="logo"
                src="https://traveazi-io-nonprod-general-revamp.s3.eu-west-2.amazonaws.com/1726627386183-linkedln.png"
                alt="linkedIn logo"
              />
            </a>
          </span>
          <span class="center-text">
            <a href="https://twitter.com/traveazi_io">
              <img
                class="logo"
                src="https://traveazi-io-nonprod-general-revamp.s3.eu-west-2.amazonaws.com/1726627422689-twitter.png"
                alt="twitter logo"
              />
            </a>
          </span>
          <span class="center-text">
            <a href="https://www.instagram.com/traveazi.io/">
              <img
                class="logo"
                src="https://traveazi-io-nonprod-general-revamp.s3.eu-west-2.amazonaws.com/1726627463049-instagram.png"
                alt="instagram logo"
              />
            </a>
          </span>
        </div>
        <aside>
          <small class="landmark"
            >Copyright &copy; <%= new Date().getFullYear() %>
          </small>
        </aside>
        <p class="center-text fw-bold">TravEazi</p>
      </footer>
    </div>
  </body>
</html>
````

## File: src/modules/mail/templates/emailnotification.ejs
````
<!doctype html>
<html>
  <meta charset="utf-8" />
  <title><%= locals.subject %></title>

  <head>
    <link
      href="https://fonts.googleapis.com/css2?family=DM+Sans&family=Inter:wght@100;200;300;400;600&family=Joan&family=Roboto:ital,wght@0,100;0,300;1,100&display=swap"
      rel="stylesheet"
    />
    <style>
      * {
        font-family: 'DM Sans', sans-serif;
        color: #000000;
        font-weight: 400;
        font-size: 14px;
        line-height: 24px;
        text-align: justify;
      }

      body {
        background: #f0f7ff;
        -webkit-font-smoothing: antialiased;
        font-size: 14px;
        line-height: 1.4;
        margin: 1.5rem;
        display: flex;
        justify-content: center;
        padding: 1rem;
        -ms-text-size-adjust: 100%;
        -webkit-text-size-adjust: 100%;
      }

      .main {
        padding: 2rem;
        width: auto;
        background: white;
        margin: 1.5rem;
        border-radius: 8px;
        box-shadow: 0px 10px 30px rgba(0, 0, 0, 0.01);
      }

      .container {
        padding: 24px;
        max-width: 600px;
        background: #eef2f5;
        border-radius: 10px;
      }

      p {
        font-size: 14px;
      }

      a {
        color: #000;
        text-decoration: none;
      }

      footer {
        margin-top: 2rem;
      }

      footer div,
      footer aside {
        display: flex;
        justify-content: space-between;
        align-items: center;
        width: 100%;
        text-align: center;
        gap: 8px;
      }

      footer div {
        width: 30%;
        margin: 16px auto;
      }

      .main-header {
        font-style: normal;
        font-weight: 700;
        font-size: 20px;
        margin-bottom: 10px;
      }

      .user-name {
        font-style: normal;
        font-size: 16px;
      }

      .fw-bold {
        font-weight: 600;
        text-decoration: none;
      }

      .bold {
        font-style: bold;
        font-size: 30px;
      }

      .center-text {
        width: 100%;
        margin: auto;
        text-align: center;
      }

      .mt-n5 {
        margin-top: -5px;
      }

      .my-50 {
        margin: 15px 0px;
        text-align: center;
      }

      main aside {
        margin-top: 16px;
        font-size: 14px;
      }

      .landmark {
        color: #616161;
        margin-bottom: 16px;
        margin: auto;
        width: 100%;
        text-align: center;
      }

      .image {
        display: block;
        width: 80px;
        margin: auto;
        object-fit: contain;
        pointer-events: none;
      }

      .logo {
        height: 30px;
        width: 30px;
        margin: auto;
      }

      img.g-img + div {
        display: none;
      }

      .content {
        padding: 0 10px;
      }

      table {
        margin: 20px 5px;
      }

      .bg-bg {
        background: #eef2f5;
        padding: 20px 10px;
        width: 30%;
        margin: 10px auto;
      }

      .bg-dark {
        color: #000;
        font-weight: 700;
      }
    </style>
  </head>

  <body>
    <div class="container">
      <a href="#">
        <img
          class="image g-img"
          src=""
          alt="TravEazi.io logo"
        />
      </a>
      <div class="main">
        <table role="presentation" cellpadding="2px" class="content">
          <p class="user-name">Hi <%= locals.name %>,</p>
          <h5>
            <%- locals.body %>
          </h5>
          <p>Best regards,</p>
              <!-- <a href="">
              <img
                class="image"
                src=<%= locals.image %>
                alt=""
              />
            </a> -->

          <p>
            <a class="bg-dark" href="https://www.traveazi.com"
              >TravEzi Support Team</a
            >
          </p>
        </table>
      </div>
      <footer>
 
        <aside>
          <small class="landmark"
            >Copyright &copy; <%= new Date().getFullYear() %>
          </small>
        </aside>
        <p class="center-text fw-bold">TravEazi</p>
      </footer>
    </div>
  </body>
</html>
````

## File: src/modules/mail/templates/marketing.ejs
````
<!doctype html>
<html>
  <meta charset="utf-8" />
  <title><%= locals.subject %></title>

  <head>
    <link
      href="https://fonts.googleapis.com/css2?family=DM+Sans&family=Inter:wght@100;200;300;400;600&family=Joan&family=Roboto:ital,wght@0,100;0,300;1,100&display=swap"
      rel="stylesheet"
    />
    <style>
      * {
        font-family: 'DM Sans', sans-serif;
        color: #000000;
        font-weight: 400;
        font-size: 14px;
        line-height: 24px;
        text-align: justify;
      }

      body {
        background: #f0f7ff;
        -webkit-font-smoothing: antialiased;
        font-size: 14px;
        line-height: 1.4;
        margin: 1.5rem;
        display: flex;
        justify-content: center;
        padding: 1rem;
        -ms-text-size-adjust: 100%;
        -webkit-text-size-adjust: 100%;
      }

      .main {
        padding: 2rem;
        width: auto;
        background: white;
        margin: 1.5rem;
        border-radius: 8px;
        box-shadow: 0px 10px 30px rgba(0, 0, 0, 0.01);
      }

      .container {
        padding: 24px;
        max-width: 600px;
        background: #eef2f5;
        border-radius: 10px;
      }

      p {
        font-size: 14px;
      }

      a {
        color: #000;
        text-decoration: none;
      }

      footer {
        margin-top: 2rem;
      }

      footer div,
      footer aside {
        display: flex;
        justify-content: space-between;
        align-items: center;
        width: 100%;
        text-align: center;
        gap: 8px;
      }

      footer div {
        width: 30%;
        margin: 16px auto;
      }

      .main-header {
        font-style: normal;
        font-weight: 700;
        font-size: 20px;
        margin-bottom: 10px;
      }

      .user-name {
        font-style: normal;
        font-size: 16px;
      }

      .fw-bold {
        font-weight: 600;
        text-decoration: none;
      }

      .bold {
        font-style: bold;
        font-size: 30px;
      }

      .center-text {
        width: 100%;
        margin: auto;
        text-align: center;
      }

      .mt-n5 {
        margin-top: -5px;
      }

      .my-50 {
        margin: 15px 0px;
        text-align: center;
      }

      main aside {
        margin-top: 16px;
        font-size: 14px;
      }

      .landmark {
        color: #616161;
        margin-bottom: 16px;
        margin: auto;
        width: 100%;
        text-align: center;
      }

      .image {
        display: block;
        width: 80px;
        margin: auto;
        object-fit: contain;
        pointer-events: none;
      }

      .logo {
        height: 30px;
        width: 30px;
        margin: auto;
      }

      img.g-img + div {
        display: none;
      }

      .content {
        padding: 0 10px;
      }

      table {
        margin: 20px 5px;
      }

      .bg-bg {
        background: #eef2f5;
        padding: 20px 10px;
        width: 30%;
        margin: 10px auto;
      }

      .bg-dark {
        color: #000;
        font-weight: 700;
      }
    </style>
  </head>

  <body>
    <div class="container">
      <a href="#">
        <img
          class="image g-img"
          src="https://traveazi-io-nonprod-general-revamp.s3.eu-west-2.amazonaws.com/1726625876998-xtern-logo.png"
          alt="traveazi.io logo"
        />
      </a>
      <div class="main">
        <table role="presentation" cellpadding="2px" class="content">
          <p class="user-name">Hi <%= locals.name %>,</p>
          <h5>
            <%= locals.body %>
          </h5>
          <p>Best regards,</p>
              <!-- <a href="">
              <img
                class="image"
                src=<%= locals.image %>
                alt=""
              />
            </a> -->

          <p>
            <a class="bg-dark" href="https://www.traveazi.ai"
              >TravEazi Support Team</a
            >
          </p>
        </table>
      </div>
      <footer>
        <div>
          <span class="center-text">
            <a href="https://www.facebook.com/official.traveazi.io/">
              <img
                class="logo"
                src="https://traveazi-io-nonprod-general-revamp.s3.eu-west-2.amazonaws.com/1726627249979-facebook.png"
                alt="facebook logo"
              />
            </a>
          </span>
          <span class="center-text">
            <a href="https://www.linkedin.com/company/traveazi-io/">
              <img
                class="logo"
                src="https://traveazi-io-nonprod-general-revamp.s3.eu-west-2.amazonaws.com/1726627386183-linkedln.png"
                alt="linkedIn logo"
              />
            </a>
          </span>
          <span class="center-text">
            <a href="https://twitter.com/traveazi_io">
              <img
                class="logo"
                src="https://traveazi-io-nonprod-general-revamp.s3.eu-west-2.amazonaws.com/1726627422689-twitter.png"
                alt="twitter logo"
              />
            </a>
          </span>
          <span class="center-text">
            <a href="https://www.instagram.com/traveazi.io/">
              <img
                class="logo"
                src="https://traveazi-io-nonprod-general-revamp.s3.eu-west-2.amazonaws.com/1726627463049-instagram.png"
                alt="instagram logo"
              />
            </a>
          </span>
        </div>
        <aside>
          <small class="landmark"
            >Copyright &copy; <%= new Date().getFullYear() %>
          </small>
        </aside>
        <p class="center-text fw-bold">TravEazi</p>
      </footer>
    </div>
  </body>
</html>
````

## File: src/modules/mail/templates/resetpassword.ejs
````
<!doctype html>
<html>
  <meta charset="utf-8" />
  <title>Reset Password | xtern.ai</title>

  <head>
    <link
      href="https://fonts.googleapis.com/css2?family=DM+Sans&family=Inter:wght@100;200;300;400;600&family=Joan&family=Roboto:ital,wght@0,100;0,300;1,100&display=swap"
      rel="stylesheet"
    />
    <style>
      * {
        font-family: 'DM Sans', sans-serif;
        color: #000000;
        font-weight: 400;
        font-size: 14px;
        line-height: 24px;
        text-align: justify;
      }

      body {
        background: #f0f7ff;
        -webkit-font-smoothing: antialiased;
        font-size: 14px;
        line-height: 1.4;
        margin: 1.5rem;
        padding: 1rem;
        display: flex;
        justify-content: center;
        -ms-text-size-adjust: 100%;
        -webkit-text-size-adjust: 100%;
      }

      .main {
        padding: 2rem;
        width: auto;
        background: white;
        margin: 1.5rem;
        border-radius: 8px;
        box-shadow: 0px 10px 30px rgba(0, 0, 0, 0.01);
      }

      .container {
        padding: 24px;
        max-width: 600px;
        background: #eef2f5;
        border-radius: 10px;
      }

      p {
        font-size: 14px;
      }

      a {
        color: #000;
        text-decoration: none;
      }

      footer {
        margin-top: 2rem;
      }

      footer div,
      footer aside {
        display: flex;
        justify-content: space-between;
        align-items: center;
        width: 100%;
        text-align: center;
        gap: 8px;
      }

      footer div {
        width: 30%;
        margin: 16px auto;
      }

      .main-header {
        font-style: normal;
        font-weight: 700;
        font-size: 20px;
        margin-bottom: 10px;
      }

      .user-name {
        font-style: normal;
        font-size: 16px;
      }

      .fw-bold {
        font-weight: 600;
        text-decoration: none;
      }

      .bold {
        font-style: bold;
        font-size: 30px;
      }

      .center-text {
        width: 100%;
        margin: auto;
        text-align: center;
      }

      .mt-n5 {
        margin-top: -5px;
      }

      .my-50 {
        margin: 15px 0px;
        text-align: center;
      }

      main aside {
        margin-top: 16px;
        font-size: 14px;
      }

      .landmark {
        color: #616161;
        margin-bottom: 16px;
        margin: auto;
        width: 100%;
        text-align: center;
      }

      .image {
        display: block;
        width: 80px;
        margin: auto;
        object-fit: contain;
        pointer-events: none;
      }

      .logo {
        height: 30px;
        width: 30px;
        margin: auto;
      }

      img.g-img + div {
        display: none;
      }

      .content {
        padding: 0 40px;
      }

      table {
        margin: 20px;
      }

      .bg-bg {
        background: #eef2f5;
        padding: 20px 10px;
        width: 30%;
        margin: 10px auto;
      }

      .bg-dark {
        color: #000;
        font-weight: 700;
      }
    </style>
  </head>

  <body>
    <div class="container">
      <a href="#">
        <img
          class="image g-img"
          src="https://traveazi-io-nonprod-general-revamp.s3.eu-west-2.amazonaws.com/1726625876998-xtern-logo.png"
          alt="traveazi.io logo"
        />
      </a>
      <div class="main">
        <table role="presentation" cellpadding="2px" class="content">
          <p class="user-name">Hi <%= locals.name %>,</p>
          <p>
            We received a request to reset password to your account. Kindly
            click the link below to proceed:
          </p>
          <h2 class="my-50 fw-bold bg-bg center-text bold">
            <a href="<%= locals.url %>">Confirm</a>
          </h2>
          <h5>
            If you didn’t request this change, please ignore this email. If you
            have any questions, feel free to contact our support team.
          </h5>
          <p>Best regards,</p>
          <p>
            <a class="bg-dark" href="https://www.traveazi.ai"
              >TravEazi Support Team</a
            >
          </p>
        </table>
      </div>
      <footer>
        <div>
          <span class="center-text">
            <a href="https://www.facebook.com/official.traveazi.io/">
              <img
                class="logo"
                src="https://traveazi-io-nonprod-general-revamp.s3.eu-west-2.amazonaws.com/1726627249979-facebook.png"
                alt="facebook logo"
              />
            </a>
          </span>
          <span class="center-text">
            <a href="https://www.linkedin.com/company/traveazi-io/">
              <img
                class="logo"
                src="https://traveazi-io-nonprod-general-revamp.s3.eu-west-2.amazonaws.com/1726627386183-linkedln.png"
                alt="linkedIn logo"
              />
            </a>
          </span>
          <span class="center-text">
            <a href="https://twitter.com/traveazi_io">
              <img
                class="logo"
                src="https://traveazi-io-nonprod-general-revamp.s3.eu-west-2.amazonaws.com/1726627422689-twitter.png"
                alt="twitter logo"
              />
            </a>
          </span>
          <span class="center-text">
            <a href="https://www.instagram.com/traveazi.io/">
              <img
                class="logo"
                src="https://traveazi-io-nonprod-general-revamp.s3.eu-west-2.amazonaws.com/1726627463049-instagram.png"
                alt="instagram logo"
              />
            </a>
          </span>
        </div>
        <aside>
          <small class="landmark"
            >Copyright &copy; <%= new Date().getFullYear() %>
          </small>
        </aside>
        <p class="center-text fw-bold">TravEazi</p>
      </footer>
    </div>
  </body>
</html>
````

## File: src/modules/passenger/dto/passenger.dto.ts
````typescript
import { BaseRegistrationDto } from 'src/modules/auth/dto/base-registeration.dto';

// Currently, no additional fields are strictly required for passenger *initial* registration
// beyond the base fields. Specific preferences might be added later during onboarding.
export class PassengerRegistrationDto extends BaseRegistrationDto {}
````

## File: src/modules/payment/payment.module.ts
````typescript
import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios'; // Import HttpModule
import { PaymentService } from './payment.service';
import { WebhookController } from './webhook.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { Booking, BookingSchema } from '../booking/schemas/booking.schema'; // Need BookingModel
import { SecretsModule } from 'src/global/secrets/module';

@Module({
  imports: [
    HttpModule, // Add HttpModule for making requests to Paystack
    MongooseModule.forFeature([
      { name: Booking.name, schema: BookingSchema }, // To update booking status
    ]),
    SecretsModule,
  ],
  providers: [PaymentService],
  controllers: [WebhookController], // Webhook controller for Paystack callbacks
  exports: [PaymentService], // Export service for BookingModule to use
})
export class PaymentModule {}
````

## File: src/modules/payment/payment.service.ts
````typescript
import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { SecretsService } from '../../global/secrets/service';
import { AxiosError } from 'axios';
import { firstValueFrom } from 'rxjs';
import * as crypto from 'crypto'; // For webhook signature verification
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Booking, BookingDocument } from '../booking/schemas/booking.schema';
import { PaymentStatus } from '../booking/enums/payment-status.enum';
import { ErrorHelper } from 'src/core/helpers';

// Define expected Paystack response structures (can be more detailed)
interface PaystackInitializeResponse {
  status: boolean;
  message: string;
  data: {
    authorization_url: string;
    access_code: string;
    reference: string;
  };
}

interface PaystackVerifyResponse {
  status: boolean;
  message: string;
  data: {
    status: 'success' | 'failed' | 'abandoned';
    reference: string;
    amount: number; // Amount is in kobo (smallest unit)
    currency: string;
    customer: {
      email: string;
    };
    metadata?: {
      // Include metadata if you send it
      bookingId?: string;
      userId?: string;
    };
    // ... other fields
  };
}

@Injectable()
export class PaymentService {
  private readonly logger = new Logger(PaymentService.name);
  private readonly paystackBaseUrl: string;
  private readonly paystackSecretKey: string;
  private readonly frontendCallbackUrl: string;

  constructor(
    private readonly httpService: HttpService,
    private readonly secretsService: SecretsService,
    @InjectModel(Booking.name) private bookingModel: Model<BookingDocument>,
  ) {
    const { secretKey, baseUrl, frontendCallbackUrl } =
      this.secretsService.paystack;
    this.paystackSecretKey = secretKey;
    this.paystackBaseUrl = baseUrl;
    this.frontendCallbackUrl = frontendCallbackUrl;

    if (!this.paystackSecretKey) {
      this.logger.error('Paystack Secret Key not configured!');
      // Potentially throw error to prevent module initialization without key
    }
  }

  private getAuthHeader() {
    return { Authorization: `Bearer ${this.paystackSecretKey}` };
  }

  async initializeTransaction(
    amountInKobo: number, // Paystack expects amount in smallest unit (kobo for NGN)
    email: string,
    bookingId: string,
    userId: string,
  ): Promise<{
    authorization_url: string;
    reference: string;
    access_code: string;
  }> {
    const url = `${this.paystackBaseUrl}/transaction/initialize`;
    // Generate a unique reference for this transaction
    const reference = `RIDEBY-${bookingId}-${Date.now()}`;

    const payload = {
      email,
      amount: amountInKobo, // Amount in kobo
      currency: 'NGN', // Assuming Nigerian Naira
      reference,
      callback_url: this.frontendCallbackUrl, // Where Paystack redirects frontend
      metadata: {
        // Send custom data to identify transaction later
        bookingId: bookingId,
        userId: userId,
        service: 'ride-by-booking',
      },
    };

    try {
      this.logger.log(
        `Initializing Paystack transaction for booking ${bookingId} with ref ${reference}`,
      );
      const response = await firstValueFrom(
        this.httpService.post<PaystackInitializeResponse>(url, payload, {
          headers: this.getAuthHeader(),
        }),
      );

      if (response.data.status && response.data.data?.authorization_url) {
        this.logger.log(
          `Paystack init successful for ref ${reference}. URL: ${response.data.data.authorization_url}`,
        );
        return response.data.data;
      } else {
        this.logger.error(
          `Paystack init failed for ref ${reference}: ${response.data.message}`,
        );
        ErrorHelper.InternalServerErrorException(
          `Payment initialization failed: ${response.data.message}`,
        );
      }
    } catch (error) {
      const axiosError = error as AxiosError;
      this.logger.error(
        `Error calling Paystack initialize API for ref ${reference}: ${axiosError.message}`,
        axiosError.stack,
      );
      const errorMsg =
        axiosError.response?.data?.['message'] ||
        axiosError.message ||
        'Payment service error';
      ErrorHelper.InternalServerErrorException(
        `Payment initialization error: ${errorMsg}`,
      );
    }
  }

  async verifyTransaction(
    reference: string,
  ): Promise<PaystackVerifyResponse['data'] | null> {
    const url = `${this.paystackBaseUrl}/transaction/verify/${reference}`;
    try {
      this.logger.log(`Verifying Paystack transaction ref ${reference}`);
      const response = await firstValueFrom(
        this.httpService.get<PaystackVerifyResponse>(url, {
          headers: this.getAuthHeader(),
        }),
      );

      if (response.data.status) {
        this.logger.log(
          `Paystack verification status for ref ${reference}: ${response.data.data.status}`,
        );
        return response.data.data;
      } else {
        this.logger.warn(
          `Paystack verify failed for ref ${reference}: ${response.data.message}`,
        );
        return null; // Or throw based on message? For webhooks, maybe return null.
      }
    } catch (error) {
      const axiosError = error as AxiosError;
      // Paystack often returns 404 for invalid reference, treat as failure
      if (axiosError.response?.status === 404) {
        this.logger.warn(
          `Paystack transaction ref ${reference} not found or invalid.`,
        );
        return null;
      }
      this.logger.error(
        `Error calling Paystack verify API for ref ${reference}: ${axiosError.message}`,
        axiosError.stack,
      );
      // Don't throw here for webhooks, allow processing to continue if possible
      return null;
    }
  }

  verifyWebhookSignature(signature: string, rawBody: string): boolean {
    if (!signature || !rawBody) {
      this.logger.warn(
        'Webhook verification failed: Missing signature or body.',
      );
      return false;
    }
    const hash = crypto
      .createHmac('sha512', this.paystackSecretKey)
      .update(rawBody) // Use the raw request body
      .digest('hex');
    const isValid = hash === signature;
    if (!isValid) {
      this.logger.warn(
        `Webhook verification failed: Signature mismatch. Expected ${hash}, Got ${signature}`,
      );
    } else {
      this.logger.log('Webhook signature verified successfully.');
    }
    return isValid;
  }

  async handleWebhook(eventPayload: any): Promise<void> {
    const { event, data } = eventPayload;
    const reference = data?.reference;

    this.logger.log(
      `Received Paystack webhook event: ${event} for reference: ${reference || 'N/A'}`,
    );

    if (!reference) {
      this.logger.warn(
        'Webhook payload missing transaction reference. Ignoring.',
      );
      return; // Cannot process without reference
    }

    // Process only relevant events (e.g., successful charge)
    if (event === 'charge.success') {
      // 1. Verify the transaction again with Paystack API for security
      const verificationData = await this.verifyTransaction(reference);

      if (!verificationData || verificationData.status !== 'success') {
        this.logger.warn(
          `Webhook event ${event} for ref ${reference} could not be verified or status is not 'success'. Ignoring.`,
        );
        return;
      }

      // 2. Extract necessary info (e.g., bookingId from metadata)
      const bookingId = verificationData.metadata?.bookingId;
      if (!bookingId) {
        this.logger.warn(
          `Webhook event ${event} for ref ${reference} missing bookingId in metadata. Cannot update booking.`,
        );
        return;
      }

      // 3. Update Booking Status
      try {
        const updatedBooking = await this.bookingModel.findOneAndUpdate(
          {
            _id: bookingId,
            transactionRef: reference,
            paymentStatus: PaymentStatus.PENDING,
          }, // Ensure we update the correct pending booking
          { $set: { paymentStatus: PaymentStatus.PAID } },
          { new: true }, // Return the updated document
        );

        if (updatedBooking) {
          this.logger.log(
            `Booking ${bookingId} payment status updated to PAID via webhook for ref ${reference}.`,
          );
          // TODO: Trigger Notification to Driver/Passenger (Phase 6)
          // await this.notificationService.notifyPaymentSuccess(updatedBooking);
        } else {
          this.logger.warn(
            `Booking ${bookingId} not found or already processed for webhook ref ${reference}.`,
          );
        }
      } catch (error) {
        this.logger.error(
          `Error updating booking ${bookingId} from webhook ref ${reference}: ${error.message}`,
          error.stack,
        );
        // Consider retry logic or dead-letter queue for failed updates
        ErrorHelper.InternalServerErrorException(
          'Webhook processing failed for booking update.',
        ); // Throw to signal error to Paystack (it might retry)
      }
    } else if (event === 'charge.failed') {
      // Handle failed payment if needed (e.g., update status to FAILED)
      const bookingId = data.metadata?.bookingId;
      if (bookingId) {
        await this.bookingModel.updateOne(
          {
            _id: bookingId,
            transactionRef: reference,
            paymentStatus: PaymentStatus.PENDING,
          },
          { $set: { paymentStatus: PaymentStatus.FAILED } },
        );
        this.logger.log(
          `Booking ${bookingId} payment status updated to FAILED via webhook for ref ${reference}.`,
        );
        // TODO: Trigger Notification?
      }
    } else {
      this.logger.log(`Ignoring Paystack webhook event type: ${event}`);
    }
  }
}
````

## File: src/modules/payment/webhook.controller.ts
````typescript
import {
  Controller,
  Post,
  Req,
  RawBodyRequest,
  Headers,
  Logger,
  HttpStatus,
  HttpCode,
} from '@nestjs/common';
import { Request } from 'express';
import { PaymentService } from './payment.service';
import { ApiTags, ApiOperation, ApiResponse, ApiHeader } from '@nestjs/swagger';
import { ErrorHelper } from 'src/core/helpers';

@ApiTags('Webhooks')
@Controller('webhooks')
export class WebhookController {
  private readonly logger = new Logger(WebhookController.name);

  constructor(private readonly paymentService: PaymentService) {}

  @Post('paystack')
  @HttpCode(HttpStatus.OK) // Paystack expects 200 OK on success
  @ApiOperation({ summary: 'Handle Paystack webhook events' })
  @ApiHeader({
    name: 'x-paystack-signature',
    description: 'Paystack webhook signature',
    required: true,
  })
  @ApiResponse({
    status: 200,
    description: 'Webhook received and processing acknowledged.',
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid payload or signature.',
  })
  @ApiResponse({ status: 403, description: 'Forbidden - Invalid signature.' })
  async handlePaystackWebhook(
    @Headers('x-paystack-signature') signature: string,
    @Req() req: RawBodyRequest<Request>, // Use RawBodyRequest to get raw body buffer
  ): Promise<{ received: boolean }> {
    // IMPORTANT: Ensure express.raw({ type: 'application/json' }) middleware is applied in main.ts
    // for routes including '/webhook' to get the raw body.
    if (!req.rawBody) {
      this.logger.error(
        'Raw body not available for webhook verification. Ensure raw body middleware is configured.',
      );
      ErrorHelper.BadRequestException('Webhook configuration error.');
    }

    const rawBodyString = req.rawBody.toString();
    this.logger.log(
      `Received Paystack webhook. Signature: ${signature ? 'Present' : 'Missing'}`,
    );

    // 1. Verify Signature
    const isValid = this.paymentService.verifyWebhookSignature(
      signature,
      rawBodyString,
    );
    if (!isValid) {
      this.logger.error('Invalid Paystack webhook signature received.');
      ErrorHelper.ForbiddenException('Invalid webhook signature.'); // Use 403 for security failures
    }

    this.logger.log('Paystack webhook signature verified.');

    // 2. Parse Payload (already parsed by default if JSON, but use rawBodyString if needed)
    const payload = req.body; // Assuming express.json() ran AFTER express.raw()

    // 3. Process Event Asynchronously (Recommended for resilience)
    // You could push this to a Bull queue instead of processing directly
    try {
      await this.paymentService.handleWebhook(payload);
    } catch (error) {
      // Log the error, but still return 200 OK to Paystack to prevent retries for processing errors
      // unless it's an error you want Paystack to retry (like temporary DB issue)
      this.logger.error(
        `Error processing Paystack webhook payload: ${error.message}`,
        error.stack,
      );
      // Potentially throw specific errors if needed, but generally acknowledge receipt
      // ErroHelper.InternalServerErrorException('Webhook processing failed.');
    }

    // 4. Acknowledge Receipt to Paystack
    // Return 200 OK immediately even if background processing is ongoing
    return { received: true };
  }
}
````

## File: src/modules/rating/dto/submit-rating.dto.ts
````typescript
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsInt,
  IsMongoId,
  IsNotEmpty,
  IsOptional,
  IsString,
  Max,
  MaxLength,
  Min,
} from 'class-validator';

export class SubmitRatingDto {
  @ApiProperty({
    description: 'ID of the completed booking being rated',
    example: '605c72ef4e79a3a3e8f2d3b4',
  })
  @IsMongoId()
  @IsNotEmpty()
  bookingId: string;

  @ApiProperty({ description: 'Rating score (1 to 5)', example: 5 })
  @IsInt()
  @Min(1)
  @Max(5)
  @IsNotEmpty()
  score: number;

  @ApiPropertyOptional({
    description: 'Optional comment for the rating',
    maxLength: 500,
    example: 'Great ride!',
  })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  comment?: string;
}
````

## File: src/modules/rating/enums/role-rated-as.enum.ts
````typescript
export enum RoleRatedAs {
  DRIVER = 'DRIVER',
  PASSENGER = 'PASSENGER',
}
````

## File: src/modules/rating/schemas/rating.schema.ts
````typescript
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { User } from '../../user/schemas/user.schema';
import { Ride } from '../../rides/schemas/ride.schema';
import { Booking } from '../../booking/schemas/booking.schema';
import { RoleRatedAs } from '../enums/role-rated-as.enum';

export type RatingDocument = Rating & Document;

@Schema({ timestamps: true, collection: 'ratings' })
export class Rating {
  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  })
  rater: User; // The user giving the rating

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  })
  ratee: User; // The user being rated

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Ride',
    required: true,
    index: true,
  })
  ride: Ride;

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Booking',
    required: true,
    index: true,
  })
  booking: Booking;

  @Prop({ type: String, enum: RoleRatedAs, required: true })
  roleRatedAs: RoleRatedAs; // Was the ratee acting as a DRIVER or PASSENGER?

  @Prop({ type: Number, required: true, min: 1, max: 5 })
  score: number;

  @Prop({ type: String, trim: true, maxlength: 500 })
  comment?: string;

  // createdAt handled by timestamps: true
}

export const RatingSchema = SchemaFactory.createForClass(Rating);

// Index to prevent duplicate ratings for the same interaction
RatingSchema.index({ rater: 1, booking: 1 }, { unique: true });
// Index to fetch ratings received by a user
RatingSchema.index({ ratee: 1, createdAt: -1 });
````

## File: src/modules/rating/rating.controller.ts
````typescript
import { Controller, Post, Body, UseGuards, Logger } from '@nestjs/common';
import { RatingService } from './rating.service';
import { SubmitRatingDto } from './dto/submit-rating.dto';
import { AuthGuard } from '../../core/guards/authenticate.guard';
import { User } from '../../core/decorators/user.decorator';
import { IUser } from '../../core/interfaces/user/user.interface';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { Rating } from './schemas/rating.schema'; // For response type hint

@ApiTags('Ratings')
@ApiBearerAuth()
@UseGuards(AuthGuard)
@Controller('ratings')
export class RatingController {
  private readonly logger = new Logger(RatingController.name);

  constructor(private readonly ratingService: RatingService) {}

  @Post()
  @ApiOperation({ summary: 'Submit a rating for a completed booking' })
  @ApiResponse({
    status: 201,
    description: 'Rating submitted successfully.',
    type: Rating,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid input or booking not completed.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - User not part of the booking.',
  })
  @ApiResponse({ status: 404, description: 'Not Found - Booking not found.' })
  @ApiResponse({
    status: 409,
    description:
      'Conflict - Rating already submitted for this booking by this user.',
  })
  async submitRating(
    @User() rater: IUser,
    @Body() submitRatingDto: SubmitRatingDto,
  ): Promise<{ message: string; data: Rating }> {
    this.logger.log(
      `User ${rater._id} submitting rating for booking ${submitRatingDto.bookingId}`,
    );
    const newRating = await this.ratingService.submitRating(
      rater._id,
      submitRatingDto,
    );
    return {
      message: 'Rating submitted successfully.',
      data: newRating.toObject() as Rating,
    };
  }
}
````

## File: src/modules/rating/rating.module.ts
````typescript
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
````

## File: src/modules/rating/rating.service.ts
````typescript
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
````

## File: src/modules/rides/dto/coordinates.dto.ts
````typescript
import { ApiProperty } from '@nestjs/swagger';
import { IsLatitude, IsLongitude, IsNotEmpty } from 'class-validator';

export class CoordinatesDto {
  @ApiProperty({ example: 6.5244, description: 'Latitude' })
  @IsLatitude()
  @IsNotEmpty()
  lat: number;

  @ApiProperty({ example: 3.3792, description: 'Longitude' })
  @IsLongitude()
  @IsNotEmpty()
  lon: number;
}
````

## File: src/modules/rides/dto/create-ride.dto.ts
````typescript
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsArray,
  IsDateString,
  //   IsLatitude,
  //   IsLongitude,
  IsMongoId,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsString,
  Min,
  ValidateNested,
  ArrayMaxSize,
} from 'class-validator';
import { CoordinatesDto } from './coordinates.dto';

export class CreateRideDto {
  @ApiProperty({
    description: 'ID of the vehicle to be used for the ride',
    example: '605c72ef4e79a3a3e8f2d3b4',
  })
  @IsMongoId()
  @IsNotEmpty()
  vehicleId: string;

  @ApiProperty({ description: 'Origin coordinates', type: CoordinatesDto })
  @ValidateNested()
  @Type(() => CoordinatesDto)
  @IsNotEmpty()
  origin: CoordinatesDto;

  @ApiProperty({ description: 'Destination coordinates', type: CoordinatesDto })
  @ValidateNested()
  @Type(() => CoordinatesDto)
  @IsNotEmpty()
  destination: CoordinatesDto;

  @ApiProperty({
    description: 'User-friendly origin address',
    example: '123 Main St, Ikeja, Lagos',
  })
  @IsString()
  @IsNotEmpty()
  originAddress: string;

  @ApiProperty({
    description: 'User-friendly destination address',
    example: '456 University Rd, Ibadan',
  })
  @IsString()
  @IsNotEmpty()
  destinationAddress: string;

  // Optional: Waypoints might be added later or via a separate update endpoint
  // @ApiPropertyOptional({ description: 'Waypoint coordinates', type: [CoordinatesDto] })
  // @IsOptional()
  // @IsArray()
  // @ValidateNested({ each: true })
  // @Type(() => CoordinatesDto)
  // waypoints?: CoordinatesDto[];

  @ApiProperty({
    description: 'Departure date and time (ISO 8601 format)',
    example: '2025-08-15T09:00:00.000Z',
  })
  @IsDateString()
  @IsNotEmpty()
  departureTime: string; // Receive as string, convert to Date in service

  @ApiProperty({
    description: 'Price per seat in NGN (or smallest currency unit)',
    example: 2500,
  })
  @IsNumber()
  @Min(0) // Allow free rides? Or set Min(100)?
  @IsNotEmpty()
  pricePerSeat: number;

  @ApiPropertyOptional({
    type: [String],
    example: ['No Smoking', 'Music allowed'],
    description: 'List of ride preferences',
  })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  @ArrayMaxSize(10)
  preferences?: string[];
}
````

## File: src/modules/rides/dto/search-rides.dto.ts
````typescript
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsDateString,
  IsInt,
  IsNotEmpty,
  IsOptional,
  Min,
  ValidateNested,
} from 'class-validator';
import { PaginationDto } from '../../../core/dto/page-options.dto'; // Adjust path
import { CoordinatesDto } from './coordinates.dto';

export class SearchRidesDto extends PaginationDto {
  // Inherit pagination fields
  @ApiProperty({
    description: 'Origin coordinates for search',
    type: CoordinatesDto,
  })
  @ValidateNested()
  @Type(() => CoordinatesDto)
  @IsNotEmpty()
  origin: CoordinatesDto;

  @ApiProperty({
    description: 'Destination coordinates for search',
    type: CoordinatesDto,
  })
  @ValidateNested()
  @Type(() => CoordinatesDto)
  @IsNotEmpty()
  destination: CoordinatesDto;

  @ApiProperty({
    description: 'Desired departure date (YYYY-MM-DD format)',
    example: '2025-08-15',
  })
  @IsDateString()
  @IsNotEmpty()
  departureDate: string; // We'll handle time range in the service

  @ApiProperty({ description: 'Number of seats required', example: 1 })
  @Type(() => Number) // Ensure transformation from query param string
  @IsInt()
  @Min(1)
  @IsNotEmpty()
  seatsNeeded: number;

  @ApiPropertyOptional({
    description:
      'Maximum distance (in meters) from specified origin/destination points',
    example: 5000,
    default: 5000,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1000) // Minimum search radius
  maxDistance?: number = 5000; // Default to 5km
}
````

## File: src/modules/rides/enums/ride-status.enum.ts
````typescript
export enum RideStatus {
  SCHEDULED = 'SCHEDULED', // Ride is planned but not started
  IN_PROGRESS = 'IN_PROGRESS', // Ride has started
  COMPLETED = 'COMPLETED', // Ride finished successfully
  CANCELLED = 'CANCELLED', // Ride was cancelled (by driver or system)
}
````

## File: src/modules/rides/interfaces/populated-ride.interface.ts
````typescript
import { BookingDocument } from '../../booking/schemas/booking.schema';
import { RideDocument } from '../schemas/ride.schema';

export interface PopulatedRideWithBookings
  extends Omit<RideDocument, 'bookings'> {
  bookings: BookingDocument[];
}
````

## File: src/modules/rides/schemas/ride.schema.ts
````typescript
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { User } from '../../user/schemas/user.schema'; // Adjust path
import { Vehicle } from '../../driver/schemas/vehicle.schema'; // Adjust path
import { RideStatus } from '../enums/ride-status.enum';

// Simple Point Schema for GeoJSON
@Schema({ _id: false }) // No separate ID for point subdocuments
class Point {
  @Prop({ type: String, enum: ['Point'], required: true, default: 'Point' })
  type: string;

  @Prop({ type: [Number], required: true }) // [longitude, latitude]
  coordinates: number[];
}
const PointSchema = SchemaFactory.createForClass(Point);

export type RideDocument = Ride & Document;

@Schema({ timestamps: true, collection: 'rides' })
export class Ride {
  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  })
  driver: User;

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Vehicle',
    required: true,
    index: true,
  })
  vehicle: Vehicle;

  @Prop({ type: PointSchema, required: true })
  origin: Point;

  @Prop({ type: PointSchema, required: true })
  destination: Point;

  @Prop({ type: [PointSchema], default: [] }) // Array of waypoints
  waypoints?: Point[];

  @Prop({ type: String, required: true })
  originAddress: string; // User-friendly origin address

  @Prop({ type: String, required: true })
  destinationAddress: string; // User-friendly destination address

  @Prop({ type: Date, required: true, index: true })
  departureTime: Date;

  @Prop({ type: Date }) // Can be calculated/updated
  estimatedArrivalTime?: Date;

  @Prop({ type: Number, required: true, min: 0 })
  initialSeats: number; // Seats the vehicle had when ride was created

  @Prop({ type: Number, required: true, min: 0 })
  availableSeats: number; // Current available seats (decreases with bookings)

  @Prop({ type: Number, required: true, min: 0 })
  pricePerSeat: number;

  @Prop({
    type: String,
    enum: RideStatus,
    default: RideStatus.SCHEDULED,
    index: true,
  })
  status: RideStatus;

  @Prop({ type: [String], default: [] })
  preferences?: string[]; // e.g., "No Smoking", "Pets Allowed"

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'Booking', default: [] })
  bookings: mongoose.Schema.Types.ObjectId[]; // Refs to Booking documents for this ride

  @Prop({ type: PointSchema, required: false, index: '2dsphere' }) // Add geospatial index if querying by location
  currentLocation?: Point;

  @Prop({ type: Date })
  lastLocationUpdate?: Date;
}

export const RideSchema = SchemaFactory.createForClass(Ride);

// Geospatial index for efficient location-based searching
RideSchema.index({ origin: '2dsphere', destination: '2dsphere' });
// Optional: Index departure time for sorting/filtering
RideSchema.index({ departureTime: 1 });
````

## File: src/modules/storage/constants/index.ts
````typescript
export * from './secret-key';
````

## File: src/modules/storage/constants/secret-key.ts
````typescript
export const secretKeys = 'awsSecretKeysToken';
````

## File: src/modules/storage/decorators/index.ts
````typescript
export * from './inject-secret';
````

## File: src/modules/storage/decorators/inject-secret.ts
````typescript
import { Inject } from '@nestjs/common';

import { secretKeys } from '../constants';

export function InjectAwsSecretKeys() {
  return Inject(secretKeys);
}
````

## File: src/modules/storage/interfaces/index.ts
````typescript
export * from './secret-key.interfaces';
````

## File: src/modules/storage/interfaces/secret-key.interfaces.ts
````typescript
export type SecretKey = {
  AWS_REGION: string;
  AWS_ACCESS_KEY_ID: string;
  AWS_SECRET_ACCESS_KEY: string;
  AWS_S3_BUCKET_NAME: string;
};
````

## File: src/modules/storage/index.ts
````typescript
export * from './s3-bucket.module';
export * from './s3-bucket.service';
````

## File: src/modules/storage/s3-bucket.module.ts
````typescript
import { Provider } from '@nestjs/common';
import { S3 } from 'aws-sdk';
import { AwsSdkModule } from 'nest-aws-sdk';
import { AwsS3Service } from './s3-bucket.service';
import { secretKeys as secretKeysToken } from './constants';
import { SecretKey } from './interfaces';
import { SecretsService } from 'src/global/secrets/service';

export class AwsS3Module {
  static forRoot(secretKey: keyof SecretsService) {
    const AwsS3SecretKeysProvider: Provider<SecretKey> = {
      provide: secretKeysToken,
      inject: [SecretsService],
      useFactory: (secretsService: SecretsService) => secretsService[secretKey],
    };

    return {
      module: AwsS3Module,
      imports: [
        AwsSdkModule.forFeatures([S3]),
        AwsSdkModule.forRootAsync({
          defaultServiceOptions: {
            useFactory: (secretsService: SecretsService) => {
              return {
                region: secretsService[secretKey].AWS_REGION,
                credentials: {
                  accessKeyId: secretsService[secretKey].AWS_ACCESS_KEY_ID,
                  secretAccessKey:
                    secretsService[secretKey].AWS_SECRET_ACCESS_KEY,
                },
                signatureVersion: 'v4',
              };
            },
            inject: [SecretsService],
          },
        }),
      ],
      providers: [AwsS3Service, AwsS3SecretKeysProvider],
      exports: [AwsS3Service],
    };
  }
}
````

## File: src/modules/storage/s3-bucket.service.ts
````typescript
import { Injectable, Logger } from '@nestjs/common';
import { S3 } from 'aws-sdk';
import { InjectAwsService } from 'nest-aws-sdk';
import { InjectAwsSecretKeys } from './decorators';
import { SecretKey } from './interfaces';

@Injectable()
export class AwsS3Service {
  private logger = new Logger(AwsS3Service.name);
  constructor(
    @InjectAwsSecretKeys() private secretKeys: SecretKey,
    @InjectAwsService(S3) private readonly s3: S3,
  ) {}

  async uploadAttachment(attachment: Express.Multer.File, fileName?: string) {
    if (!attachment) {
      return null;
    }

    fileName = fileName || this.generateFileName(attachment);
    const bucket = this.secretKeys.AWS_S3_BUCKET_NAME;

    const params = {
      Bucket: bucket,
      Key: fileName,
      Body: attachment.buffer,
      ACL: 'public-read',
    };

    const s3Response = await this.s3.upload(params).promise();

    return s3Response.Location;
  }

  private generateFileName(attachment: Express.Multer.File) {
    return `${Date.now()}-${attachment.originalname}`.replace(/\s/g, '_');
  }

  async upload(params: S3.Types.PutObjectRequest) {
    return this.s3.upload(params).promise();
  }

  async uploadToS3(fileBuffer: Buffer, fileName: string): Promise<string> {
    const bucket = this.secretKeys.AWS_S3_BUCKET_NAME;

    const params: AWS.S3.PutObjectRequest = {
      Bucket: bucket,
      Key: fileName,
      Body: fileBuffer,
      ACL: 'public-read',
    };

    const s3Response = await this.s3.upload(params).promise();
    return s3Response.Location;
  }
}
````

## File: src/modules/trip-sharing/trip-sharing.controller.ts
````typescript
import { Controller, Get, Param, Logger } from '@nestjs/common';
import { TripSharingService } from './trip-sharing.service'; // Create this service
import { ApiTags, ApiOperation, ApiResponse, ApiParam } from '@nestjs/swagger';
import { ErrorHelper } from 'src/core/helpers';

@ApiTags('Public - Trip Sharing')
@Controller('trip')
export class TripSharingController {
  private readonly logger = new Logger(TripSharingController.name);

  constructor(private readonly tripSharingService: TripSharingService) {}

  @Get(':shareToken')
  @ApiOperation({
    summary: 'Get basic public status of a shared trip using a token',
  })
  @ApiParam({
    name: 'shareToken',
    description: 'The unique token from the share link',
  })
  @ApiResponse({
    status: 200,
    description: 'Basic trip details.',
    schema: {
      /* Define limited DTO here */
    },
  })
  @ApiResponse({
    status: 404,
    description: 'Not Found - Invalid or expired share token.',
  })
  @ApiResponse({ status: 500, description: 'Internal server error.' })
  async getSharedTripStatus(
    @Param('shareToken') shareToken: string,
  ): Promise<{ message: string; data: any }> {
    this.logger.log(
      `Public request for trip status with token: ${shareToken.substring(0, 8)}...`,
    );
    const tripData =
      await this.tripSharingService.getTripStatusByToken(shareToken);
    if (!tripData) {
      ErrorHelper.NotFoundException('Invalid or expired share link.');
    }
    return {
      message: 'Trip status retrieved successfully.',
      data: tripData, // Service should return limited data
    };
  }
}
````

## File: src/modules/trip-sharing/trip-sharing.module.ts
````typescript
import { Module } from '@nestjs/common';
import { TripSharingService } from './trip-sharing.service';
import { TripSharingController } from './trip-sharing.controller';
import { RedisModule } from '@nestjs-modules/ioredis'; // Needs Redis access
import { MongooseModule } from '@nestjs/mongoose';
import { Ride, RideSchema } from '../rides/schemas/ride.schema';
import { SecretsService } from 'src/global/secrets/service'; // Needed for Redis config

@Module({
  imports: [
    // Configure Redis specifically for this module or rely on global
    RedisModule.forRootAsync({
      useFactory: ({ userSessionRedis }: SecretsService) => ({
        // Reuse userSessionRedis config or create separate one
        type: 'single',
        url: `redis://${userSessionRedis.REDIS_USER}:${userSessionRedis.REDIS_PASSWORD}@${userSessionRedis.REDIS_HOST}:${userSessionRedis.REDIS_PORT}`,
      }),
      inject: [SecretsService],
    }),
    MongooseModule.forFeature([
      { name: Ride.name, schema: RideSchema }, // Need RideModel
    ]),
  ],
  providers: [TripSharingService],
  controllers: [TripSharingController],
})
export class TripSharingModule {}
````

## File: src/modules/trip-sharing/trip-sharing.service.ts
````typescript
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
````

## File: src/modules/twilio/twiio.module.ts
````typescript
import { Module } from '@nestjs/common';
import { TwilioService } from './twilio.service';
import { SecretsModule } from '../../global/secrets/module';

@Module({
  imports: [SecretsModule],
  providers: [TwilioService],
  exports: [TwilioService],
})
export class TwilioModule {}
````

## File: src/modules/user/dto/emergency-contact.dto.ts
````typescript
import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsNotEmpty,
  IsPhoneNumber,
  IsString,
  MaxLength,
  ValidateNested,
} from 'class-validator';

class EmergencyContactItemDto {
  @ApiProperty({ description: "Contact's full name", example: 'Jane Doe' })
  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  name: string;

  @ApiProperty({
    description: "Contact's phone number (Nigerian format)",
    example: '+2348012345678',
  })
  @IsPhoneNumber('NG', {
    message:
      'Please provide a valid Nigerian phone number for the emergency contact.',
  })
  @IsNotEmpty()
  phone: string;
}

export class UpdateEmergencyContactsDto {
  @ApiProperty({
    description: 'List of emergency contacts (maximum 3)',
    type: [EmergencyContactItemDto], // Array of the nested DTO
    minItems: 0, // Allow empty array to clear contacts
    maxItems: 3, // Set maximum contacts
  })
  @IsArray()
  @ValidateNested({ each: true }) // Validate each item in the array
  @ArrayMinSize(0)
  @ArrayMaxSize(3, {
    message: 'You can add a maximum of 3 emergency contacts.',
  })
  @Type(() => EmergencyContactItemDto) // Important for nested validation
  contacts: EmergencyContactItemDto[];
}
````

## File: src/modules/user/schemas/action.schema.ts
````typescript
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { ActionEnum, Subject } from 'src/core/interfaces';

@Schema({
  timestamps: true,
})
export class Action {
  @Prop({ enum: ActionEnum, default: ActionEnum.Read })
  action: ActionEnum;

  @Prop({
    type: String,
  })
  subject: Subject;

  @Prop()
  description: string;
}

export const ActionSchema = SchemaFactory.createForClass(Action);
````

## File: src/modules/user/schemas/role.schema.ts
````typescript
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { RoleNameEnum } from 'src/core/interfaces';
import { Action, ActionSchema } from './action.schema';

@Schema({
  timestamps: true,
})
export class Role extends Document {
  @Prop({
    type: String,
    nullable: false,
    unique: true,
  })
  name: RoleNameEnum;

  @Prop({
    type: String,
    nullable: true,
  })
  description: string;

  @Prop({
    type: [ActionSchema],
  })
  actions: Action[];
}

export const roleSchema = SchemaFactory.createForClass(Role);
````

## File: src/modules/user/schemas/token.schema.ts
````typescript
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MSchema } from 'mongoose';
import { User } from './user.schema';

@Schema({
  timestamps: true,
})
export class Token extends Document {
  @Prop({ type: MSchema.Types.ObjectId, ref: 'User' })
  user: User;

  @Prop({ required: true, type: String })
  code: string;

  @Prop({ type: Boolean, default: false })
  isUsed: boolean;

  @Prop({ required: false, type: Date })
  expirationTime: Date;
}

export const TokenSchema = SchemaFactory.createForClass(Token);
````

## File: src/modules/user/user.controller.ts
````typescript
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
  ApiBody,
} from '@nestjs/swagger';
import {
  Patch,
  Controller,
  UseGuards,
  Logger,
  Body,
  Delete,
  Post,
} from '@nestjs/common'; // Import Patch
import { UpdateEmergencyContactsDto } from '../user/dto/emergency-contact.dto'; // Import DTO
import { UserService } from '../user/user.service'; // Import UserService
import { AuthGuard } from 'src/core/guards';
import { IUser } from 'src/core/interfaces';
import { User } from 'src/core/decorators';
import { RegisterDeviceDto } from '../user/dto/register-device.dto';

@ApiTags('User') // Modify tag if adding profile endpoints
@Controller('user')
export class UserController {
  private readonly logger = new Logger(UserController.name);
  constructor(
    private userService: UserService, // Inject UserService
  ) {}

  // ... (existing auth endpoints) ...

  @Patch('/profile/emergency-contacts') // Use PATCH for updates
  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: "Update the logged-in user's emergency contacts" })
  @ApiResponse({
    status: 200,
    description: 'Emergency contacts updated successfully.' /* type: User? */,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid input data.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({ status: 404, description: 'Not Found - User not found.' })
  async updateEmergencyContacts(
    @User() currentUser: IUser,
    @Body() updateDto: UpdateEmergencyContactsDto,
  ): Promise<{ message: string; data?: any }> {
    // Return success message
    this.logger.log(`User ${currentUser._id} updating emergency contacts.`);
    await this.userService.updateEmergencyContacts(currentUser._id, updateDto);
    return {
      message: 'Emergency contacts updated successfully.',
      // Optionally return updated contacts or user profile snippet
    };
  }

  @Post('devices/register')
  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Register a device token for push notifications' })
  @ApiResponse({ status: 200, description: 'Device registered successfully.' })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({ status: 400, description: 'Bad Request - Missing token.' })
  async registerDevice(
    @User() currentUser: IUser,
    @Body() dto: RegisterDeviceDto,
  ): Promise<{ message: string }> {
    await this.userService.addDeviceToken(currentUser._id, dto.deviceToken);
    return { message: 'Device registered successfully.' };
  }

  @Delete('devices/unregister') // Use DELETE method
  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Unregister a device token for push notifications' })
  @ApiResponse({
    status: 200,
    description: 'Device unregistered successfully.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiBody({ type: RegisterDeviceDto }) // Reuse DTO for body structure
  async unregisterDevice(
    @User() currentUser: IUser,
    @Body() dto: RegisterDeviceDto, // Get token from body
  ): Promise<{ message: string }> {
    await this.userService.removeDeviceToken(currentUser._id, dto.deviceToken);
    return { message: 'Device unregistered successfully.' };
  }
}
````

## File: src/modules/app.gateway.ts
````typescript
import { Logger } from '@nestjs/common';
import {
  OnGatewayConnection,
  OnGatewayDisconnect,
  WebSocketGateway,
  WebSocketServer,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { WsGuard } from 'src/core/guards';
import { ErrorHelper } from 'src/core/helpers';

@WebSocketGateway({
  cors: {
    origin: '*',
  },
  path: '/api/chat/socket',
})
export class AppGateway implements OnGatewayConnection, OnGatewayDisconnect {
  constructor(private wsGuard: WsGuard) {}

  private logger = new Logger('WebsocketGateway');

  @WebSocketServer()
  server: Server;

  handleDisconnect(client: Socket) {
    this.logger.log(`Client disconnected: ${client.id}`);
  }

  async handleConnection(client: Socket) {
    try {
      this.logger.log(`Client handleConnection: ${client.id}`);

      const user = await this.wsGuard.verifyAccessToken(
        client.handshake.auth.token || client.handshake.headers.authorization,
      );

      if (!user) {
        ErrorHelper.UnauthorizedException('User is not authorized');
      }

      client.data.user = user;

      client.join(user._id.toString());

      this.logger.log(`Client connected: ${client.id}`);
    } catch (error) {
      this.logger.log(`has issues: ${client.id}`);
      client.emit('exception', error.message);
      client.disconnect();
    }
  }
}
````

## File: test/jest-e2e.json
````json
{
  "moduleFileExtensions": ["js", "json", "ts"],
  "rootDir": ".",
  "testEnvironment": "node",
  "testRegex": ".e2e-spec.ts$",
  "transform": {
    "^.+\\.(t|j)s$": "ts-jest"
  }
}
````

## File: .eslintrc.js
````javascript
module.exports = {
  parser: '@typescript-eslint/parser',
  parserOptions: {
    project: 'tsconfig.json',
    tsconfigRootDir: __dirname,
    sourceType: 'module',
  },
  plugins: ['@typescript-eslint/eslint-plugin'],
  extends: [
    'plugin:@typescript-eslint/recommended',
    'plugin:prettier/recommended',
  ],
  root: true,
  env: {
    node: true,
    jest: true,
  },
  ignorePatterns: ['.eslintrc.js'],
  rules: {
    '@typescript-eslint/interface-name-prefix': 'off',
    '@typescript-eslint/explicit-function-return-type': 'off',
    '@typescript-eslint/explicit-module-boundary-types': 'off',
    '@typescript-eslint/no-explicit-any': 'off',
  },
};
````

## File: .gitignore
````
# compiled output
/dist
/node_modules
/build

# Logs
logs
*.log
npm-debug.log*
pnpm-debug.log*
yarn-debug.log*
yarn-error.log*
lerna-debug.log*

# OS
.DS_Store

# Tests
/coverage
/.nyc_output

# IDEs and editors
/.idea
.project
.classpath
.c9/
*.launch
.settings/
*.sublime-workspace

# IDE - VSCode
.vscode/*
!.vscode/settings.json
!.vscode/tasks.json
!.vscode/launch.json
!.vscode/extensions.json

# dotenv environment variable files
.env
.env.development.local
.env.test.local
.env.production.local
.env.local

# temp directory
.temp
.tmp

# Runtime data
pids
*.pid
*.seed
*.pid.lock

# Diagnostic reports (https://nodejs.org/api/report.html)
report.[0-9]*.[0-9]*.[0-9]*.[0-9]*.json

/config/firebase-service-account.json
````

## File: .prettierrc
````
{
  "singleQuote": true,
  "trailingComma": "all"
}
````

## File: instructions.md
````markdown
# Nigerian Intercity Carpooling Platform: Backend (NestJS) - Current State Analysis

## 1. Project Overview

This document summarizes the current state of the NestJS backend for the Nigerian Intercity Carpooling platform. The goal of the platform is to connect private car owners (Drivers) traveling between Nigerian cities with passengers (Passengers) seeking rides along the same routes, addressing issues of cost, convenience, and safety in intercity travel.

This summary is based on the provided codebase (`repomix-output.md`) and informed by the features and requirements outlined in the initial MVP PRD and the subsequent Comprehensive Product Overview document.

**Target Audience for this Document:** LLMs and Developers needing context on the existing backend structure and components to guide further development.

## 2. Technology Stack (Backend)

*   **Framework:** NestJS (v11.x) - A progressive Node.js framework using TypeScript.
*   **Language:** TypeScript
*   **Database:** MongoDB (via Mongoose ORM)
*   **Authentication:** JWT (JSON Web Tokens), Phone number OTP (implied, infrastructure partially present), Password Hashing (bcryptjs)
*   **Session Management:** Redis (via `@nestjs-modules/ioredis` and custom `UserSessionService`)
*   **Real-time Communication:** Socket.IO with Redis Adapter (for potential future features like real-time tracking/messaging)
*   **Asynchronous Tasks:** Bull (potentially for background jobs like email sending)
*   **Email:** Nodemailer (via `@nestjs-modules/mailer`) with EJS templates.
*   **Configuration:** `@nestjs/config` (using `.env` files)
*   **API Documentation:** Swagger (`@nestjs/swagger`)
*   **Validation:** `class-validator`, `class-transformer`
*   **Linting/Formatting:** ESLint, Prettier

## 3. Core Architectural Concepts

*   **Modular Design:** The application is structured into NestJS modules (`src/modules`).
*   **Global Modules:** Common services and utilities like configuration (`SecretsModule`), token generation (`TokenHelper`), and user session management (`UserSessionModule`) are grouped in `src/global` and exposed globally.
*   **Core Abstractions:** Reusable components like Guards (`AuthGuard`), Filters (`HttpExceptionFilter`), Interceptors (`LoggerInterceptor`, `TransformInterceptor`), Decorators (`User`), Helpers (`EncryptHelper`, `ErrorHelper`), and base DTOs (Pagination) are located in `src/core`.
*   **API Structure:** Primarily follows RESTful principles, managed through Controllers and Services.
*   **Data Handling:** Uses Mongoose Schemas for MongoDB interaction and DTOs (Data Transfer Objects) for API request/response validation and shaping.
*   **Error Handling:** Centralized HTTP exception filtering (`HttpExceptionFilter`) and a utility class (`ErrorHelper`) for standardized error responses.
*   **Request/Response Handling:** Uses interceptors for logging (`LoggerInterceptor`) and standardizing response format (`TransformInterceptor`).

## 4. Directory Structure Overview
src/
├── app.module.ts # Root application module
├── main.ts # Application entry point (bootstrap)
│
├── core/ # Core framework elements (guards, filters, helpers, base DTOs, etc.)
│ ├── adpater/ # WebSocket adapters (RedisIoAdapter)
│ ├── constants/ # Application-wide constants (messages, patterns)
│ ├── decorators/ # Custom decorators (@User)
│ ├── dto/ # Base DTOs (Pagination)
│ ├── enums/ # Core enumerations (PortalType)
│ ├── filters/ # Exception filters (HttpExceptionFilter)
│ ├── guards/ # Authentication/Authorization guards (AuthGuard)
│ ├── helpers/ # Utility helpers (Encryption, Error Handling)
│ ├── interceptors/ # Request/Response interceptors (Logging, Transformation)
│ ├── interfaces/ # TypeScript interfaces (User, HTTP, Roles)
│ ├── redis/ # Redis module configuration helper
│ └── validators/ # Custom class-validators
│
├── global/ # Globally available modules and services
│ ├── secrets/ # Configuration service (SecretsService)
│ ├── user-session/ # Redis-based user session management
│ ├── utils/ # Utility classes (TokenHelper)
│ └── global.module.ts # Module consolidating global providers
│
└── modules/ # Feature-specific modules
├── auth/ # Authentication, User Registration, Login, Password Mgmt
├── config/ # (Placeholder) Configuration module?
├── database/ # (Placeholder) Database configuration module?
├── driver/ # (Placeholder) Driver-specific logic
├── geolocation/ # (Placeholder) Geolocation-related logic
├── health/ # Health check endpoint (/health-check)
├── mail/ # Email sending functionality (Mailer, Templates, Events)
├── rides/ # (Placeholder) Ride management logic
└── users/ # (Placeholder) User management logic (potentially merged with Auth)


## 5. Module Breakdown & Functionality

*   **`AppModule` (`app.module.ts`):**
    *   The root module, importing necessary configuration (`ConfigModule`, `SecretsModule`), database connection (`MongooseModule`), and feature modules.
*   **`GlobalModule` (`global/global.module.ts`):**
    *   Provides `SecretsService`, `TokenHelper`, and `UserSessionService` globally.
*   **`AuthModule` (`modules/auth/`):**
    *   **Purpose:** Handles user identity, authentication, and core profile actions.
    *   **Components:**
        *   `AuthController`: Exposes endpoints for registration (`/create-user`), login (`/login`), email verification (`/confirmation`, `/resend-verification`), password reset (`/forgot-password`, `/reset-password`), logout (`/logout`), fetching user info (`/user`), changing password (`/change-password`), avatar upload (`/user/upload-avatar`), role fetching (`/roles`, `/users`).
        *   `AuthService`: Contains the business logic for user creation, validation, login, token generation, session management, password handling, email verification flows, avatar upload coordination (mentions `AwsS3Service` - integration needed).
        *   `DTOs`: Defines data structures for requests (e.g., `AuthDto`, `LoginDto`, `UpdateUserDto`, `ForgotPasswordDto`).
        *   **Entities/Schemas Used:** `User`, `Token`, `Role`.
    *   **Key Features Implemented:** Email/Password registration & login, JWT generation & verification, Redis session management, Email confirmation flow, Forgot/Reset password flow, Logout, Basic user profile fetch/update, Avatar upload (logic points to AWS S3, but service implementation not shown), Role fetching.
    *   **PRD Alignment:** Covers core Authentication and Profile Management requirements. Handles different `PortalType` (DRIVER, PASSENGER, ADMIN).
*   **`UserSessionModule` (`global/user-session/`):**
    *   **Purpose:** Manages user sessions using Redis.
    *   **Components:** `UserSessionService` provides methods to create, get, check, and delete user sessions based on user ID and a unique `sessionId` stored within the JWT. Supports "remember me" functionality.
    *   **PRD Alignment:** Crucial for maintaining user login state and security.
*   **`MailModule` (`modules/mail/`):**
    *   **Purpose:** Handles sending emails for various events.
    *   **Components:**
        *   `MailController`: Internal controller likely triggered by events or queues.
        *   `MailService`: Uses `@nestjs-modules/mailer` to send emails using EJS templates (`confirmation.ejs`, `resetpassword.ejs`, etc.).
        *   `MailEvent`: Service to trigger specific email sends (e.g., `sendUserConfirmation`, `sendResetPassword`).
        *   `EmailProcessor`: (Implied by filename `email.processor.ts`) Likely a Bull queue processor for handling email jobs asynchronously.
        *   `EmailSchema`: Mongoose schema potentially for logging email events/statuses.
        *   `Templates`: EJS files for email content.
    *   **PRD Alignment:** Fulfills requirements for sending verification and notification emails. Integration with Bull suggests asynchronous handling.
*   **`HealthModule` (`modules/health/`):**
    *   **Purpose:** Provides an endpoint (`/health-check`) to monitor application health.
    *   **Components:** `HealthController` uses `@nestjs/terminus` to check the status of dependencies (currently MongoDB).
    *   **PRD Alignment:** Good practice for monitoring and deployment.
*   **`SecretsModule` (`global/secrets/`):**
    *   **Purpose:** Loads and provides access to environment variables and configuration.
    *   **Components:** `SecretsService` extends `ConfigService` to provide typed access to secrets (DB credentials, JWT secret, Mail credentials, Redis config).
    *   **PRD Alignment:** Essential for secure configuration management.
*   **Placeholder Modules:**
    *   `RidesModule`, `RidersModule` (Driver), `GeolocationModule`, `UsersModule`, `ConfigModule`, `DatabaseModule`: These exist as empty module files (`@Module({})`). They represent planned areas of functionality that are **not yet implemented**.
    *   **PRD Alignment:** These correspond directly to core features (Ride Management, Driver specifics, Geolocation, Payments) outlined in the PRDs but require significant development.

## 6. Core Utilities & Shared Components (`src/core/`)

*   **`AuthGuard`:** Middleware to protect routes, verifying JWTs using `TokenHelper` and checking Redis sessions via `UserSessionService`.
*   **`HttpExceptionFilter`:** Catches HTTP exceptions and standardizes the error response format (`{ success: false, statusCode, message }`).
*   **`LoggerInterceptor` & `TransformInterceptor`:** Logs incoming requests and formats successful responses consistently (`{ success: true, data, message, meta? }`). Handles pagination responses specifically.
*   **`EncryptHelper`:** Wrapper around `bcryptjs` for hashing and comparing passwords.
*   **`ErrorHelper`:** Utility class to throw standardized `HttpException` types (BadRequest, Unauthorized, NotFound, etc.).
*   **`TokenHelper` (`global/utils/`):** Generates and verifies JWTs (access tokens, potentially refresh tokens, password reset tokens). Generates random strings/numbers (useful for OTPs, session IDs).
*   **Base DTOs:** `PaginationDto`, `PaginationResultDto`, `PaginationMetadataDto` provide a standard way to handle paginated API responses.
*   **`RedisIoAdapter`:** Custom Socket.IO adapter using Redis for potential multi-instance scaling of real-time features.

## 7. Database Schema (Mongoose Models Identified)

*   **`User` (`modules/auth/entities/schemas/user.schema.ts` - *Inferred Path*):**
    *   Fields: `firstName`, `lastName`, `email`, `password`, `avatar`, `about`, `country`, `gender`, `phoneNumber`, `emailConfirm`, `status`, `strategy` (Local, Google etc.), `portalType`, `roles` (Ref to Role), `lastSeen`, `createdAt`, `hasChangedPassword`.
    *   *PRD Alignment:* Covers User Data requirements for both Drivers and Passengers, including verification status and basic profile info. Needs extension for Driver-specific vehicle details.
*   **`Token` (`modules/user/schemas/token.entity.ts`):**
    *   Fields: `user` (Ref to User), `code` (likely for OTP/verification), `expiresAt`.
    *   *PRD Alignment:* Supports OTP-based verification flows (Email confirmation, Password reset).
*   **`Role` (`modules/admin/entities/role.entity.ts` - *Inferred Path*):**
    *   Fields: `name` (Enum: ADMIN, DRIVER, PASSENGER), `description`, `actions` (Permissions).
    *   *PRD Alignment:* Supports role-based access control, differentiating user types.
*   **`Email` (`modules/mail/schema/email.schema.ts`):**
    *   Fields: `event`, `email`, `timestamp`, `message_id`, etc. (Likely for tracking email sending status/webhooks).
*   **Placeholder Schemas:** `Rider`, `Rides` are mentioned in `MailModule` imports but their definitions are not included in the provided code dump. These are critical for core functionality.
*   **`Country` (`modules/seed/schemas/country.schema.ts` - *Inferred Path*):** Seems to be related to user profile data, possibly for dropdowns or validation.

## 8. External Integrations

*   **Implemented/Partially Implemented:**
    *   **Redis:** Used for User Session caching (`UserSessionService`) and Socket.IO scaling (`RedisIoAdapter`). Configured via `SecretsService`.
    *   **MongoDB:** Primary database, connection managed by `MongooseModule` using URI from `SecretsService`.
    *   **Nodemailer:** Used for sending emails via SMTP (`MailService`). Configured via `SecretsService`.
    *   **Bull:** Queue system (likely using Redis backend) for background tasks, specifically set up for email processing (`MailModule`, `EmailProcessor`).
    *   **Swagger:** API documentation generation.
*   **Mentioned/Required but Not Fully Implemented:**
    *   **Payment Gateways (Paystack, Flutterwave):** Explicitly required by PRD for payments. **No code present.**
    *   **Mapping Services (Google Maps, etc.):** Required by PRD for route visualization, geocoding, distance calculation. **No code present.**
    *   **SMS Providers:** Required by PRD for OTP phone verification. `TokenHelper` can generate OTPs, but **no SMS sending integration code present.**
    *   **AWS S3:** Mentioned in `AuthService` for avatar uploads. **`AwsS3Service` is referenced but its implementation is missing.**

## 9. Configuration & Environment

*   Managed by `SecretsService` which reads from `.env` files.
*   Key configurations include: `PORT`, `MONGO_URI`, `JWT_SECRET`, `MAIL_*` credentials, `REDIS_*` credentials.

## 10. Testing

*   Basic E2E test setup (`test/app.e2e-spec.ts`) using `supertest`.
*   Jest configuration present (`jest.config.js`, `test/jest-e2e.json`).
*   **No unit tests** specific to services or controllers were included in the dump.

## 11. Summary & Next Steps (Backend Focus)

**Current Strengths:**

*   Solid foundation using NestJS best practices (Modules, Services, Controllers, DI).
*   Core Authentication (Register, Login, JWT, Session), User Profile basics, and Notification (Email) systems are partially implemented.
*   Robust configuration management (`SecretsService`).
*   Infrastructure for background jobs (Bull) and real-time features (Socket.IO + Redis) is present.
*   Basic error handling and response standardization are in place.
*   API documentation setup (Swagger).

**Key Areas for Immediate Development (based on PRDs and missing code):**

1.  **Ride Management Module (`RidesModule`):**
    *   Implement `Rides` schema (origin, destination, waypoints, schedule, price, seats, status). Use geospatial indexing.
    *   Develop `RidesService` and `RidesController` for:
        *   Drivers: Creating, publishing, updating, canceling rides.
        *   Passengers: Searching rides (by location, date), filtering.
        *   Geospatial queries for searching.
2.  **Booking Management:**
    *   Implement `Booking` schema (linking User, Ride, status, payment info).
    *   Develop services/endpoints for:
        *   Passengers: Requesting/Booking rides, viewing bookings.
        *   Drivers: Viewing/Accepting/Rejecting booking requests.
3.  **Payment Integration (`PaymentModule`):**
    *   Integrate with Nigerian payment gateways (Paystack/Flutterwave).
    *   Implement services for:
        *   Fare calculation.
        *   Initiating payments upon booking confirmation.
        *   Handling payment callbacks/webhooks.
        *   Recording transactions.
        *   Handling payouts/refunds (longer term).
4.  **Driver Specifics (`DriverModule` / extend `AuthModule`):**
    *   Add Vehicle information to the `User` schema or a separate `Vehicle` schema (make, model, year, plate number, documents).
    *   Implement endpoints/services for driver vehicle registration and document upload (using the planned `AwsS3Service`).
    *   Implement driver verification logic.
5.  **Geolocation Module (`GeolocationModule`):**
    *   Integrate with a Mapping Service API.
    *   Implement services for:
        *   Geocoding (address to coordinates).
        *   Reverse Geocoding (coordinates to address).
        *   Route calculation (distance, estimated duration).
        *   Real-time location tracking (requires WebSocket integration).
6.  **Safety Features:**
    *   Implement backend logic for Trip Sharing (generating shareable links/tokens).
    *   Add Emergency Contact fields to `User` schema and endpoints to manage them.
    *   Implement Rating/Review system (schemas and services for Users to rate each other post-ride).
7.  **Communication:**
    *   Implement backend logic for in-app messaging (potentially using WebSockets/Redis pub-sub). Store messages.
    *   Integrate Push Notification service (e.g., FCM, APNS) for real-time updates.
    *   Integrate SMS Provider for phone number OTP verification.
8.  **Refine Existing Modules:**
    *   Add comprehensive validation (DTOs).
    *   Implement role-based authorization checks more granularly where needed.
    *   Develop Unit and Integration tests.
    *   Complete `AwsS3Service` implementation.

This document provides a snapshot of the backend's current state. Development should prioritize building out the placeholder modules (`Rides`, `Driver`, `Geolocation`, `Payment`) and integrating the required third-party services to meet the core functionality outlined in the PRDs.
````

## File: README.md
````markdown
<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="120" alt="Nest Logo" /></a>
</p>

[circleci-image]: https://img.shields.io/circleci/build/github/nestjs/nest/master?token=abc123def456
[circleci-url]: https://circleci.com/gh/nestjs/nest

  <p align="center">A progressive <a href="http://nodejs.org" target="_blank">Node.js</a> framework for building efficient and scalable server-side applications.</p>
    <p align="center">
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/v/@nestjs/core.svg" alt="NPM Version" /></a>
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/l/@nestjs/core.svg" alt="Package License" /></a>
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/dm/@nestjs/common.svg" alt="NPM Downloads" /></a>
<a href="https://circleci.com/gh/nestjs/nest" target="_blank"><img src="https://img.shields.io/circleci/build/github/nestjs/nest/master" alt="CircleCI" /></a>
<a href="https://coveralls.io/github/nestjs/nest?branch=master" target="_blank"><img src="https://coveralls.io/repos/github/nestjs/nest/badge.svg?branch=master#9" alt="Coverage" /></a>
<a href="https://discord.gg/G7Qnnhy" target="_blank"><img src="https://img.shields.io/badge/discord-online-brightgreen.svg" alt="Discord"/></a>
<a href="https://opencollective.com/nest#backer" target="_blank"><img src="https://opencollective.com/nest/backers/badge.svg" alt="Backers on Open Collective" /></a>
<a href="https://opencollective.com/nest#sponsor" target="_blank"><img src="https://opencollective.com/nest/sponsors/badge.svg" alt="Sponsors on Open Collective" /></a>
  <a href="https://paypal.me/kamilmysliwiec" target="_blank"><img src="https://img.shields.io/badge/Donate-PayPal-ff3f59.svg" alt="Donate us"/></a>
    <a href="https://opencollective.com/nest#sponsor"  target="_blank"><img src="https://img.shields.io/badge/Support%20us-Open%20Collective-41B883.svg" alt="Support us"></a>
  <a href="https://twitter.com/nestframework" target="_blank"><img src="https://img.shields.io/twitter/follow/nestframework.svg?style=social&label=Follow" alt="Follow us on Twitter"></a>
</p>
  <!--[![Backers on Open Collective](https://opencollective.com/nest/backers/badge.svg)](https://opencollective.com/nest#backer)
  [![Sponsors on Open Collective](https://opencollective.com/nest/sponsors/badge.svg)](https://opencollective.com/nest#sponsor)-->

## Description

[Nest](https://github.com/nestjs/nest) framework TypeScript starter repository.

## Project setup

```bash
$ npm install
```

## Compile and run the project

```bash
# development
$ npm run start

# watch mode
$ npm run start:dev

# production mode
$ npm run start:prod
```

## Run tests

```bash
# unit tests
$ npm run test

# e2e tests
$ npm run test:e2e

# test coverage
$ npm run test:cov
```

## Deployment

When you're ready to deploy your NestJS application to production, there are some key steps you can take to ensure it runs as efficiently as possible. Check out the [deployment documentation](https://docs.nestjs.com/deployment) for more information.

If you are looking for a cloud-based platform to deploy your NestJS application, check out [Mau](https://mau.nestjs.com), our official platform for deploying NestJS applications on AWS. Mau makes deployment straightforward and fast, requiring just a few simple steps:

```bash
$ npm install -g mau
$ mau deploy
```

With Mau, you can deploy your application in just a few clicks, allowing you to focus on building features rather than managing infrastructure.

## Resources

Check out a few resources that may come in handy when working with NestJS:

- Visit the [NestJS Documentation](https://docs.nestjs.com) to learn more about the framework.
- For questions and support, please visit our [Discord channel](https://discord.gg/G7Qnnhy).
- To dive deeper and get more hands-on experience, check out our official video [courses](https://courses.nestjs.com/).
- Deploy your application to AWS with the help of [NestJS Mau](https://mau.nestjs.com) in just a few clicks.
- Visualize your application graph and interact with the NestJS application in real-time using [NestJS Devtools](https://devtools.nestjs.com).
- Need help with your project (part-time to full-time)? Check out our official [enterprise support](https://enterprise.nestjs.com).
- To stay in the loop and get updates, follow us on [X](https://x.com/nestframework) and [LinkedIn](https://linkedin.com/company/nestjs).
- Looking for a job, or have a job to offer? Check out our official [Jobs board](https://jobs.nestjs.com).

## Support

Nest is an MIT-licensed open source project. It can grow thanks to the sponsors and support by the amazing backers. If you'd like to join them, please [read more here](https://docs.nestjs.com/support).

## Stay in touch

- Author - [Kamil Myśliwiec](https://twitter.com/kammysliwiec)
- Website - [https://nestjs.com](https://nestjs.com/)
- Twitter - [@nestframework](https://twitter.com/nestframework)

## License

Nest is [MIT licensed](https://github.com/nestjs/nest/blob/master/LICENSE).
````

## File: tsconfig.build.json
````json
{
  "extends": "./tsconfig.json",
  "exclude": ["node_modules", "test", "dist", "**/*spec.ts"]
}
````

## File: tsconfig.json
````json
{
  "compilerOptions": {
    "module": "commonjs",
    "declaration": true,
    "removeComments": true,
    "emitDecoratorMetadata": true,
    "experimentalDecorators": true,
    "allowSyntheticDefaultImports": true,
    "target": "ES2021",
    "sourceMap": true,
    "outDir": "./dist",
    "baseUrl": "./",
    "incremental": true,
    "skipLibCheck": true,
    "strictNullChecks": false,
    "noImplicitAny": false,
    "strictBindCallApply": false,
    "forceConsistentCasingInFileNames": false,
    "noFallthroughCasesInSwitch": false
  }
}
````

## File: src/core/adpater/index.ts
````typescript
export * from './redis.adpater';
````

## File: src/core/constants/base.constant.ts
````typescript
export const PASSWORD_PATTERN = '^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.{8,})';
export const BASE_COMMISSION = 0.3;
export const DRIVER_ONBOARDING_STEPS = 8;
export const PASSENGER_ONBOARDING_STEPS = 5;
````

## File: src/core/constants/messages.constant.ts
````typescript
export const INVALID_EMAIL_OR_PASSWORD = 'Invalid email or password';
export const INVALID_USER = 'Invalid user';
export const INVALID_CODE = 'Invalid code or expired';
export const INVALID_CODE_FORGOT_PASSWORD =
  "This link has expired. You can't change your password using this link";
export const INVALID_TOKEN = 'Invalid token';
export const EMAIL_ALREADY_EXISTS = 'Email already exists';
export const USER_DOESNT_EXIST = 'User Not Found';
export const PORTAL_TYPE_ERROR = 'Please specify portal type';

export const STORY_ASSIGNED = 'A story have been assigned to you.';
export const STORY_UPDATED = 'A story assigned to you was updated';
export const SUBTASK_ASSIGNED = 'A subtask have been assigned to you.';
export const WELCOME_MESSAGE = 'Welcome to Xtern.ai';
export const SLA_BREACH = 'SLA Breach';
export const SLA_WARNING = 'SLA Warning';
````

## File: src/core/decorators/index.ts
````typescript
export * from './user.decorator';
````

## File: src/core/decorators/user.decorator.ts
````typescript
/* eslint-disable @typescript-eslint/no-explicit-any */
import { createParamDecorator, ExecutionContext } from '@nestjs/common';

import { IUser } from '../../core/interfaces';

export const User = createParamDecorator<any, any>(
  (data: string, ctx: ExecutionContext): IUser | any => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;

    // eslint-disable-next-line security/detect-object-injection
    return data ? user[data] : user;
  },
);
````

## File: src/core/dto/index.ts
````typescript
export * from './page-meta.dto';
export * from './page-options.dto';
export * from './pagination.dto';
````

## File: src/core/enums/auth.enum.ts
````typescript
export enum PortalType {
  DRIVER = 'DRIVER',
  PASSENGER = 'PASSENGER',
  ADMIN = 'ADMIN',
}
````

## File: src/core/guards/authenticate.guard.ts
````typescript
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
} from '@nestjs/common';

import { ErrorHelper } from '../../core/helpers';
import { IUser, RequestHeadersEnum } from '../../core/interfaces';
import { TokenHelper } from '../../global/utils/token.utils';
import { UserSessionService } from '../../global/user-session/service';

@Injectable()
export class AuthGuard implements CanActivate {
  private logger = new Logger(AuthGuard.name);

  constructor(
    private tokenHelper: TokenHelper,
    private userSession: UserSessionService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();

    const authorization =
      req.headers[RequestHeadersEnum.Authorization] ||
      String(req.cookies.accessToken);

    if (!authorization) {
      ErrorHelper.ForbiddenException('Authorization header is required');
    }

    const user = await this.verifyAccessToken(authorization);

    req.user = user;

    return true;
  }

  async verifyAccessToken(authorization: string): Promise<IUser> {
    const [bearer, accessToken] = authorization.split(' ');

    if (bearer == 'Bearer' && accessToken !== '') {
      const user = this.tokenHelper.verify<IUser & { sessionId: string }>(
        accessToken,
      );

      const session = await this.userSession.get(user._id);

      if (!session) {
        this.logger.error(`verifyAccessToken: Session not found ${user._id}`);
        ErrorHelper.UnauthorizedException('Unauthorized!');
      }

      if (session.sessionId !== user.sessionId) {
        this.logger.error(
          `verifyAccessToken: SessionId not match ${session.sessionId} - ${user.sessionId}`,
        );
        ErrorHelper.UnauthorizedException('Unauthorized');
      }

      return user;
    } else {
      this.logger.error(`verifyAccessToken: Invalid token ${accessToken}`);
      ErrorHelper.UnauthorizedException('Unauthorized');
    }
  }
}
````

## File: src/core/helpers/index.ts
````typescript
export * from './error.utils';
export * from './ecrypt.helper';
export * from './date.helper';
````

## File: src/core/interfaces/http/index.ts
````typescript
export * from './http.interface';
````

## File: src/core/interfaces/user/role.interface.ts
````typescript
export enum RoleNameEnum {
  Admin = 'ADMIN',
  Driver = 'DRIVER',
  Passenger = 'PASSENGER',
}

export enum ActionEnum {
  Manage = 'manage',
  Create = 'create',
  Read = 'read',
  Update = 'update',
  Delete = 'delete',
}

export enum Subject {
  UserManagement = 'USER_MANAGEMENT',
  RideManagement = 'RIDE_MANAGEMENT',
}

export interface IAction {
  action: ActionEnum;
  subject: Subject;
  description: string;
}

export interface IRole {
  name: RoleNameEnum;
  description: string;
  actions: IAction[];
}
````

## File: src/global/secrets/module.ts
````typescript
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { SecretsService } from './service';

@Module({
  imports: [
    ConfigModule.forRoot({
      envFilePath: ['.env'],
      isGlobal: true,
    }),
  ],
  providers: [SecretsService],
  exports: [SecretsService],
})
export class SecretsModule {}
````

## File: src/modules/auth/dto/index.ts
````typescript
export * from './auth.dto';
export * from './update-user.dto';
````

## File: src/modules/booking/booking.controller.ts
````typescript
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
````

## File: src/modules/booking/booking.module.ts
````typescript
import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { BookingService } from './booking.service';
import { BookingController } from './booking.controller';
import { Booking, BookingSchema } from './schemas/booking.schema';
import { Ride, RideSchema } from '../rides/schemas/ride.schema'; // Need RideModel
import { User, UserSchema } from '../user/schemas/user.schema'; // Need UserModel
import { PaymentModule } from '../payment/payment.module';
// Import RidesModule or Service if needed for direct calls (e.g., check availability)

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Booking.name, schema: BookingSchema },
      { name: Ride.name, schema: RideSchema }, // Provide RideModel
      { name: User.name, schema: UserSchema }, // Provide UserModel
    ]),
    // RidesModule, // If needed
    PaymentModule,
  ],
  providers: [BookingService],
  controllers: [BookingController],
  exports: [BookingService], // Export if needed
})
export class BookingModule {}
````

## File: src/modules/booking/booking.service.ts
````typescript
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
import { PaymentService } from '../payment/payment.service';
import { NotificationService } from '../notification/notification.service';

@Injectable()
export class BookingService {
  private readonly logger = new Logger(BookingService.name);

  constructor(
    @InjectModel(Booking.name) private bookingModel: Model<Booking>,
    @InjectModel(Ride.name) private rideModel: Model<RideDocument>,
    @InjectModel(User.name) private userModel: Model<User>,
    private readonly notificationService: NotificationService,
    private readonly paymentService: PaymentService,
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

      try {
        const driver = await this.userModel
          .findById(ride.driver)
          .select('deviceTokens');

        await this.notificationService.sendNotificationToUser(
          driver._id.toString(),
          'New Booking Request',
          `Passenger ${passenger.firstName} wants to book ${newBooking.seatsBooked} seat(s) on your ride.`,
          { bookingId: newBooking._id.toString(), type: 'BOOKING_REQUEST' },
        );
      } catch (notificationError) {
        this.logger.error(
          `Failed to send booking request notification to driver ${ride.driver}: ${notificationError.message}`,
        );
      }

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

  async initiateBookingPayment(
    passengerId: string,
    bookingId: string,
  ): Promise<{
    authorization_url: string;
    reference: string;
    access_code: string;
  }> {
    this.logger.log(
      `Passenger ${passengerId} initiating payment for booking ${bookingId}`,
    );
    if (!mongoose.Types.ObjectId.isValid(bookingId)) {
      ErrorHelper.BadRequestException('Invalid Booking ID format.');
    }

    // 1. Find booking and verify ownership and status
    const booking = await this.bookingModel
      .findById(bookingId)
      .populate<{ passenger: UserDocument }>('passenger', 'email'); // Populate passenger email

    if (!booking) {
      ErrorHelper.NotFoundException(`Booking with ID ${bookingId} not found.`);
    }
    if (booking.passenger._id.toString() !== passengerId) {
      ErrorHelper.ForbiddenException('You can only pay for your own bookings.');
    }
    // Allow payment only if CONFIRMED and PENDING payment
    if (booking.status !== BookingStatus.CONFIRMED) {
      ErrorHelper.BadRequestException(
        `Booking must be confirmed by the driver before payment (current status: ${booking.status}).`,
      );
    }
    if (booking.paymentStatus !== PaymentStatus.PENDING) {
      // Allow retrying FAILED? For now, only PENDING.
      ErrorHelper.BadRequestException(
        `Payment for this booking is not pending (current status: ${booking.paymentStatus}).`,
      );
    }
    if (booking.totalPrice <= 0) {
      ErrorHelper.BadRequestException('This booking does not require payment.');
    }

    // 2. Call Payment Service to initialize transaction
    try {
      // Convert NGN price to kobo for Paystack
      const amountInKobo = Math.round(booking.totalPrice * 100);
      const paymentData = await this.paymentService.initializeTransaction(
        amountInKobo,
        booking.passenger.email, // Use passenger's email
        bookingId,
        passengerId,
      );

      // 3. Store transaction reference on the booking (important for webhook matching)
      await this.bookingModel.updateOne(
        { _id: bookingId },
        { $set: { transactionRef: paymentData.reference } },
      );
      this.logger.log(
        `Stored Paystack reference ${paymentData.reference} for booking ${bookingId}`,
      );

      return paymentData; // Return { authorization_url, reference, access_code }
    } catch (error) {
      this.logger.error(
        `Error initiating payment for booking ${bookingId}: ${error.message}`,
        error.stack,
      );
      // Rethrow the error from PaymentService or a generic one
      if (error instanceof HttpException) throw error;
      ErrorHelper.InternalServerErrorException('Failed to initiate payment.');
    }
  }

  async completeBookingByDriver(
    driverId: string,
    bookingId: string,
  ): Promise<BookingDocument> {
    this.logger.log(
      `Driver ${driverId} attempting to mark booking ${bookingId} as completed.`,
    );
    if (!mongoose.Types.ObjectId.isValid(bookingId)) {
      ErrorHelper.BadRequestException('Invalid Booking ID format.');
    }

    // 1. Find booking, verify driver and status
    const booking = await this.bookingModel.findById(bookingId);
    if (!booking) {
      ErrorHelper.NotFoundException(`Booking with ID ${bookingId} not found.`);
    }
    if (booking.driver.toString() !== driverId) {
      ErrorHelper.ForbiddenException(
        'You can only complete bookings for rides you are driving.',
      );
    }
    // Allow completion only if CONFIRMED (or potentially IN_PROGRESS if you add that status)
    if (booking.status !== BookingStatus.CONFIRMED) {
      ErrorHelper.BadRequestException(
        `Booking must be confirmed to be marked as completed (current status: ${booking.status}).`,
      );
    }

    // Optionally: Check if Ride departureTime has passed significantly

    // 2. Update Status
    booking.status = BookingStatus.COMPLETED;
    await booking.save();

    this.logger.log(
      `Booking ${bookingId} marked as COMPLETED by driver ${driverId}.`,
    );

    // TODO: Trigger Notification to Passenger (Phase 6)
    // TODO: Check if all bookings for the ride are completed/cancelled, then update Ride status (maybe background job)

    return booking;
  }
}
````

## File: src/modules/driver/schemas/vehicle.schema.ts
````typescript
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { User } from '../../user/schemas/user.schema'; // Adjust path
import { VehicleVerificationStatus } from 'src/core/enums/vehicle.enum';

export type VehicleDocument = Vehicle & Document;

@Schema({ timestamps: true })
export class Vehicle {
  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  })
  driver: User;

  @Prop({ type: String, required: true, trim: true })
  make: string; // e.g., Toyota

  @Prop({ type: String, required: true, trim: true })
  model: string; // e.g., Camry

  @Prop({ type: Number, required: true })
  year: number;

  @Prop({ type: String, required: true, trim: true })
  color: string;

  @Prop({
    type: String,
    required: true,
    unique: true,
    uppercase: true,
    trim: true,
    index: true,
  })
  plateNumber: string;

  @Prop({
    type: Number,
    required: true,
    min: 1,
    comment: 'Number of seats available for passengers (excluding driver)',
  })
  seatsAvailable: number;

  @Prop({ type: String })
  vehicleRegistrationImageUrl?: string;

  @Prop({ type: String })
  proofOfOwnershipImageUrl?: string; // e.g., Vehicle license

  @Prop({ type: String })
  vehicleInsuranceImageUrl?: string;

  @Prop({ type: Date })
  insuranceExpiryDate?: Date;

  @Prop({
    type: String,
    enum: VehicleVerificationStatus,
    default: VehicleVerificationStatus.NOT_SUBMITTED,
  })
  vehicleVerificationStatus: VehicleVerificationStatus;

  @Prop({ type: String })
  vehicleRejectionReason?: string;

  @Prop({ type: Boolean, default: false })
  isDefault: boolean; // If the driver has multiple vehicles, which one is primary

  @Prop({ type: [String], default: [] }) // Array of strings like "Air Conditioning", "USB Charging"
  features?: string[];
}

export const VehicleSchema = SchemaFactory.createForClass(Vehicle);
````

## File: src/modules/driver/driver.controller.ts
````typescript
import {
  Controller,
  Post,
  Body,
  UseGuards,
  Logger,
  Param,
  UploadedFile,
  UseInterceptors,
  ParseEnumPipe,
  Get,
} from '@nestjs/common';
import { DriverService } from './driver.service';
import { RegisterVehicleDto } from './dto/register-vehicle.dto';
import { AuthGuard } from '../../core/guards/authenticate.guard';
import { User } from '../../core/decorators/user.decorator';
import { IUser } from '../../core/interfaces/user/user.interface';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiConsumes,
  ApiBody,
} from '@nestjs/swagger';
import { Vehicle } from './schemas/vehicle.schema'; // Import for response type
import { VehicleDocumentType } from './enums/vehicle-document-type.enum';
import { ErrorHelper } from 'src/core/helpers';

@ApiTags('Driver')
@ApiBearerAuth() // Requires JWT token
@UseGuards(AuthGuard) // Protect all routes in this controller
@Controller('driver') // Base path for vehicle-related driver actions
export class DriverController {
  private readonly logger = new Logger(DriverController.name);

  constructor(private readonly driverService: DriverService) {}

  @Post('vehicles/register')
  @ApiOperation({ summary: 'Register a new vehicle for the logged-in driver' })
  @ApiResponse({
    status: 201,
    description: 'Vehicle registered successfully.',
    type: Vehicle,
  }) // Use the schema class for response type hint
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid input data.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized - Invalid token.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - User is not a driver.',
  })
  @ApiResponse({
    status: 409,
    description: 'Conflict - Plate number already exists.',
  })
  async registerVehicle(
    @User() driver: IUser, // Get authenticated user from decorator
    @Body() registerVehicleDto: RegisterVehicleDto,
  ): Promise<{ message: string; data: Vehicle }> {
    // Adjust return type for standard response
    this.logger.log(
      `Received request to register vehicle from driver ID: ${driver._id}`,
    );
    const newVehicle = await this.driverService.registerVehicle(
      driver._id,
      registerVehicleDto,
    );
    return {
      message: 'Vehicle registered successfully.',
      data: newVehicle.toObject() as Vehicle, // Convert Mongoose doc to plain object
    };
  }

  @Post(':vehicleId/documents')
  @UseInterceptors(FileInterceptor('documentFile')) // 'documentFile' is the field name in the form-data
  @ApiOperation({ summary: 'Upload a document for a specific vehicle' })
  @ApiConsumes('multipart/form-data') // Specify content type for file upload
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        documentFile: {
          // Must match FileInterceptor field name
          type: 'string',
          format: 'binary',
          description:
            'The vehicle document file (e.g., registration, insurance).',
        },
        documentType: {
          type: 'string',
          enum: Object.values(VehicleDocumentType), // Use enum values for Swagger
          description: 'The type of document being uploaded.',
        },
        // Optionally add other fields like insuranceExpiryDate here if needed
      },
      required: ['documentFile', 'documentType'], // Mark required fields
    },
  })
  @ApiResponse({
    status: 201,
    description: 'Document uploaded successfully.',
    type: Vehicle,
  })
  @ApiResponse({
    status: 400,
    description:
      'Bad Request - Missing file, invalid type, or invalid vehicle ID.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Driver does not own vehicle.',
  })
  @ApiResponse({ status: 404, description: 'Not Found - Vehicle not found.' })
  async uploadVehicleDocument(
    @User() driver: IUser,
    @Param('vehicleId') vehicleId: string, // Use @Param for path parameters
    @UploadedFile() file: Express.Multer.File, // Get the uploaded file
    @Body(
      'documentType',
      new ParseEnumPipe(VehicleDocumentType, {
        // Validate documentType against enum
        exceptionFactory: () =>
          ErrorHelper.BadRequestException('Invalid document type specified.'),
      }),
    )
    documentType: VehicleDocumentType,
  ): Promise<{ message: string; data: Vehicle }> {
    if (!file) {
      ErrorHelper.BadRequestException('Document file is required.');
    }
    this.logger.log(
      `Received request to upload ${documentType} for vehicle ${vehicleId} from driver ${driver._id}`,
    );
    const updatedVehicle = await this.driverService.uploadVehicleDocument(
      driver._id,
      vehicleId,
      file,
      documentType,
    );
    return {
      message: `${documentType} uploaded successfully.`,
      data: updatedVehicle.toObject() as Vehicle,
    };
  }

  @Get('profile-status')
  @ApiOperation({
    summary: "Get the logged-in driver's profile and verification status",
  })
  @ApiResponse({
    status: 200,
    description:
      'Driver profile and status retrieved.' /* type: User - define a specific Response DTO */,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - User is not a driver.',
  }) // Should be caught by role check in service/guard
  @ApiResponse({ status: 404, description: 'Not Found - Driver not found.' })
  async getDriverProfileStatus(
    @User() driver: IUser,
  ): Promise<{ message: string; data: any }> {
    // Use 'any' or create specific DTO
    this.logger.log(`Fetching profile status for driver ${driver._id}`);
    const profileData = await this.driverService.getDriverProfileAndStatus(
      driver._id,
    );
    return {
      message: 'Driver profile and status fetched successfully.',
      data: profileData, // Return the selected data
    };
  }
}
````

## File: src/modules/driver/driver.service.ts
````typescript
import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Vehicle, VehicleDocument } from './schemas/vehicle.schema';
import { User, UserDocument } from '../user/schemas/user.schema'; // Verify path
import { RoleNameEnum } from '../../core/interfaces/user/role.interface';
import { RegisterVehicleDto } from './dto/register-vehicle.dto';
import { ErrorHelper } from 'src/core/helpers'; // Use ErrorHelper for consistency
import { AwsS3Service } from '../storage/s3-bucket.service'; // Import S3 Service
import { VehicleDocumentType } from './enums/vehicle-document-type.enum';
import { VehicleVerificationStatus } from 'src/core/enums/vehicle.enum';

@Injectable()
export class DriverService {
  private readonly logger = new Logger(DriverService.name);

  constructor(
    @InjectModel(Vehicle.name) private vehicleModel: Model<VehicleDocument>,
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private readonly awsS3Service: AwsS3Service,
  ) {}

  async registerVehicle(
    driverId: string,
    dto: RegisterVehicleDto,
  ): Promise<VehicleDocument> {
    this.logger.log(
      `Attempting to register vehicle for driver ID: ${driverId}`,
    );

    // 1. Verify User is a Driver
    const driver = await this.userModel.findById(driverId).populate('roles');
    if (!driver) {
      this.logger.warn(`Driver not found for ID: ${driverId}`);
      ErrorHelper.NotFoundException('Driver user not found.');
    }
    const isDriverRole = driver.roles.some(
      (role) => role.name === RoleNameEnum.Driver,
    );
    if (!isDriverRole) {
      this.logger.warn(`User ${driverId} does not have DRIVER role.`);
      ErrorHelper.ForbiddenException('User is not registered as a driver.');
    }

    // 2. Check for duplicate plate number (case-insensitive suggested)
    const plateUpper = dto.plateNumber.toUpperCase();
    const existingVehicle = await this.vehicleModel.findOne({
      plateNumber: plateUpper,
    });
    if (existingVehicle) {
      this.logger.warn(
        `Vehicle with plate number ${plateUpper} already exists.`,
      );
      ErrorHelper.ConflictException(
        `Vehicle with plate number ${dto.plateNumber} already exists.`,
      );
    }

    // 3. Create and Save Vehicle
    try {
      const newVehicle = new this.vehicleModel({
        ...dto,
        plateNumber: plateUpper, // Store uppercase
        driver: driverId, // Link to the driver user
        // vehicleVerificationStatus defaults to NOT_SUBMITTED via schema
      });
      await newVehicle.save();
      this.logger.log(
        `Vehicle ${newVehicle._id} created successfully for driver ${driverId}.`,
      );

      // 4. Update User's vehicles array
      await this.userModel.findByIdAndUpdate(driverId, {
        $push: { vehicles: newVehicle._id },
      });
      this.logger.log(`Updated driver ${driverId}'s vehicle list.`);

      return newVehicle; // Return the saved document
    } catch (error) {
      this.logger.error(
        `Error registering vehicle for driver ${driverId}: ${error.message}`,
        error.stack,
      );
      if (error.code === 11000) {
        // Handle potential race condition for unique index
        ErrorHelper.ConflictException(
          `Vehicle with plate number ${dto.plateNumber} already exists.`,
        );
      }
      ErrorHelper.InternalServerErrorException('Failed to register vehicle.');
    }
  }

  async uploadVehicleDocument(
    driverId: string,
    vehicleId: string,
    file: Express.Multer.File,
    documentType: VehicleDocumentType,
  ): Promise<VehicleDocument> {
    this.logger.log(
      `Attempting to upload document type ${documentType} for vehicle ${vehicleId} by driver ${driverId}`,
    );

    if (!file) {
      ErrorHelper.BadRequestException('Document file is required.');
    }

    // 1. Find vehicle and verify ownership
    const vehicle = await this.vehicleModel.findById(vehicleId);
    if (!vehicle) {
      ErrorHelper.NotFoundException(`Vehicle with ID ${vehicleId} not found.`);
    }
    // Ensure the driver owns this vehicle - Use .toString() for ObjectId comparison
    if (vehicle.driver.toString() !== driverId) {
      this.logger.warn(
        `Driver ${driverId} attempted to upload document for vehicle ${vehicleId} they don't own.`,
      );
      ErrorHelper.ForbiddenException(
        'You are not authorized to modify this vehicle.',
      );
    }

    // 2. Upload to S3
    let fileUrl: string;
    try {
      // Define a structured key/filename for S3
      const s3FileName = `vehicle-documents/${driverId}/${vehicleId}/${documentType}-${Date.now()}-${file.originalname}`;
      fileUrl = await this.awsS3Service.uploadAttachment(file, s3FileName);
      this.logger.log(`Document uploaded to S3: ${fileUrl}`);
    } catch (error) {
      this.logger.error(
        `Failed to upload vehicle document to S3: ${error.message}`,
        error.stack,
      );
      ErrorHelper.InternalServerErrorException('Failed to upload document.');
    }

    // 3. Determine which field to update
    let updateField: string;
    switch (documentType) {
      case VehicleDocumentType.REGISTRATION:
        updateField = 'vehicleRegistrationImageUrl';
        break;
      case VehicleDocumentType.INSURANCE:
        updateField = 'vehicleInsuranceImageUrl';
        break;
      case VehicleDocumentType.PROOF_OF_OWNERSHIP:
        updateField = 'proofOfOwnershipImageUrl';
        break;
      case VehicleDocumentType.ROADWORTHINESS:
        updateField = 'roadworthinessImageUrl';
        break;
      // Add cases for other document types if needed
      default:
        this.logger.error(`Invalid document type provided: ${documentType}`);
        ErrorHelper.BadRequestException('Invalid document type specified.');
    }

    // 4. Update Vehicle Document in DB
    try {
      // Update the specific field and potentially the status if it wasn't already PENDING or VERIFIED
      const updateData: Partial<Vehicle> = { [updateField]: fileUrl };
      if (
        vehicle.vehicleVerificationStatus ===
          VehicleVerificationStatus.NOT_SUBMITTED ||
        vehicle.vehicleVerificationStatus === VehicleVerificationStatus.REJECTED
      ) {
        // Optionally set to PENDING automatically on first upload or re-upload after rejection
        // updateData.vehicleVerificationStatus = VehicleVerificationStatus.PENDING;
        // More robust logic might check if ALL required docs are present before setting PENDING.
        // For now, just upload the URL. Verification status change can be manual via admin or a separate trigger.
      }

      const updatedVehicle = await this.vehicleModel.findByIdAndUpdate(
        vehicleId,
        { $set: updateData },
        { new: true }, // Return the updated document
      );

      if (!updatedVehicle) {
        // Should not happen if findById worked, but good practice
        ErrorHelper.NotFoundException(
          `Vehicle with ID ${vehicleId} disappeared during update.`,
        );
      }

      this.logger.log(
        `Updated vehicle ${vehicleId} with document URL for type ${documentType}.`,
      );
      return updatedVehicle;
    } catch (error) {
      this.logger.error(
        `Failed to update vehicle ${vehicleId} in DB after S3 upload: ${error.message}`,
        error.stack,
      );
      // Consider attempting to delete the uploaded S3 file on DB update failure (compensation logic)
      ErrorHelper.InternalServerErrorException(
        'Failed to save document information.',
      );
    }
  }
  async getDriverProfileAndStatus(
    driverId: string,
  ): Promise<Partial<UserDocument>> {
    this.logger.log(`Fetching profile and status for driver ${driverId}`);
    const driver = await this.userModel
      .findById(driverId)
      .select('+driverVerificationStatus +driverRejectionReason +status') // Explicitly select status fields if needed
      .populate<{ vehicles: VehicleDocument[] }>({
        // Populate vehicles with status
        path: 'vehicles',
        select:
          'make model year plateNumber vehicleVerificationStatus vehicleRejectionReason',
      });

    if (!driver) {
      ErrorHelper.NotFoundException('Driver user not found.');
    }
    // Add role check if necessary, though AuthGuard likely implies user exists
    // const isDriverRole = driver.roles.some(role => role.name === RoleNameEnum.Driver);
    // if (!isDriverRole) { throw new ForbiddenException('User is not a driver.'); }

    // Return relevant profile info + verification statuses
    return {
      _id: driver._id,
      firstName: driver.firstName,
      lastName: driver.lastName,
      email: driver.email,
      avatar: driver.avatar,
      status: driver.status,
      driverVerificationStatus: driver.driverVerificationStatus,
      driverRejectionReason: driver.driverRejectionReason,
      vehicles: driver.vehicles,
    };
  }
}
````

## File: src/modules/geolocation/geolocation.module.ts
````typescript
import { Module } from '@nestjs/common';
import { GeolocationService } from './geolocation.service';
import { SecretsModule } from 'src/global/secrets/module';

@Module({
  imports: [SecretsModule],
  providers: [GeolocationService],
  exports: [GeolocationService],
})
export class GeolocationModule {}
````

## File: src/modules/mail/enums/index.ts
````typescript
export * from './mail.enum';
````

## File: src/modules/mail/enums/mail.enum.ts
````typescript
export enum MailType {
  USER_CONFIRMATION = 'USER_CONFIRMATION',
  RESET_PASSWORD = 'RESET_PASSWORD',
  USER_CREDENTIALS = 'USER_CREDENTIALS',
  IN_APP_EMAIL = 'IN_APP_EMAIL',
  ANNOUNCEMENTS = 'ANNOUNCEMENTS',
  REMINDERS = 'REMINDERS',
  UPDATES = 'UPDATES',
}
````

## File: src/modules/mail/mail.event.ts
````typescript
import { Injectable, Logger } from '@nestjs/common';
import { SecretsService } from 'src/global/secrets/service';
import { MailType } from './enums';
import { MailController } from './mail.controller';
import { Queue } from 'bull';
import { InjectQueue } from '@nestjs/bull';
import { UserService } from '../user/user.service';

@Injectable()
export class MailEvent {
  private logger = new Logger(MailEvent.name);
  constructor(
    @InjectQueue('emailQueue') private emailQueue: Queue,
    private secretService: SecretsService,
    private mailController: MailController,
    private userService: UserService,
  ) {}

  async sendUserConfirmation(user, code: string) {
    const sendMailDto = {
      to: [user.email],
      subject: 'Welcome to TravEazy! Confirm your Email',
      type: MailType.USER_CONFIRMATION,
      data: {
        firstName: user.firstName || 'User',
        email: user.email,
        code,
      },
      saveAsNotification: false,
    };

    await this.mailController.sendMail(sendMailDto);
  }

  async sendResetPassword(user, token: string, callbackURL?: string) {
    const url = new URL(callbackURL);
    url.searchParams.append('code', token);
    this.logger.log('url', url);

    const sendMailDto = {
      to: [user.email],
      subject: 'Reset Password - TraveEazy',
      type: MailType.RESET_PASSWORD,
      data: {
        firstName: user.firstName || 'User',
        url,
      },
      saveAsNotification: false,
    };

    await this.mailController.sendMail(sendMailDto);
  }

  async sendUserCredentials(user, password: string) {
    const sendMailDto = {
      to: [user.email],
      subject: 'Welcome to TravEazy! Here are your login credentials',
      type: MailType.USER_CREDENTIALS,
      data: {
        firstName: user.firstName || 'User',
        email: user.email,
        password,
      },
      saveAsNotification: false,
    };

    await this.mailController.sendMail(sendMailDto);
  }
}
````

## File: src/modules/mail/mail.module.ts
````typescript
import { Module } from '@nestjs/common';
import { MailerModule } from '@nestjs-modules/mailer';
import { EjsAdapter } from '@nestjs-modules/mailer/dist/adapters/ejs.adapter';
import { join } from 'path';
import { MailController } from './mail.controller';
import { MailService } from './mail.service';
import { SecretsModule } from 'src/global/secrets/module';
import { SecretsService } from 'src/global/secrets/service';
import { BullModule } from '@nestjs/bull';
import { MongooseModule } from '@nestjs/mongoose';
import { Email, EmailSchema } from './schema/email.schema';
import { UserModule } from '../user/user.module';
import { MailEvent } from './mail.event';
import { EmailProcessor } from './cron-job/email.processor';
import { TokenSchema, Token } from '../user/schemas/token.schema';
import { UserSchema, User } from '../user/schemas/user.schema';
import { roleSchema, Role } from '../user/schemas/role.schema';

@Module({
  imports: [
    SecretsModule,
    UserModule,
    MailerModule.forRootAsync({
      useFactory: ({ mailSecret }: SecretsService) => ({
        transport: {
          host: mailSecret.MAIL_HOST,
          port: mailSecret.MAIL_PORT,
          auth: {
            user: mailSecret.MAIL_USERNAME,
            pass: mailSecret.MAIL_PASSWORD,
          },
        },
        pool: true, // Enable connection pooling
        maxConnections: 5, // Limit number of connections
        maxMessages: 100, // Limit number of messages per connection
        tls: {
          rejectUnauthorized: false,
        },
        defaults: {
          from: '"No Reply" <no-reply@TravEazi.com>',
        },
        preview: true,
        template: {
          dir: join(__dirname, 'templates'),
          adapter: new EjsAdapter(),
          options: {
            strict: false,
          },
        },
      }),
      inject: [SecretsService],
      imports: [SecretsModule],
    }),
    // Register Bull queue for email processing
    BullModule.forRootAsync({
      useFactory: ({ userSessionRedis }: SecretsService) => ({
        redis: {
          host: userSessionRedis.REDIS_HOST,
          port: userSessionRedis.REDIS_PORT,
          password: userSessionRedis.REDIS_PASSWORD,
        },
      }),
      inject: [SecretsService],
      imports: [SecretsModule],
    }),

    BullModule.registerQueue({
      name: 'emailQueue', // Name of the queue for email jobs
    }),
    MongooseModule.forFeature([
      {
        name: Email.name,
        schema: EmailSchema,
      },
      { name: Token.name, schema: TokenSchema },
      { name: User.name, schema: UserSchema },
      { name: Role.name, schema: roleSchema },
    ]),
  ],
  controllers: [MailController],
  providers: [MailService, MailEvent, MailController, EmailProcessor],
  exports: [MailService, MailEvent, BullModule, MailController],
})
export class MailModule {}
````

## File: src/modules/mail/mail.service.ts
````typescript
import { Injectable, Logger } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import * as ejs from 'ejs';
import * as fs from 'fs';
import { SendMailDto } from './dto/mail.dto';
import { Email } from './schema/email.schema';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';

@Injectable()
export class MailService {
  private logger = new Logger(MailService.name);
  private from = '"TravEazi Team" <notifications@TravEazi.com>';

  private confirmationTemplate = fs.readFileSync(
    __dirname + '/templates/confirmation.ejs',
    { encoding: 'utf-8' },
  );

  private resetpasswordTemplate = fs.readFileSync(
    __dirname + '/templates/resetpassword.ejs',
    { encoding: 'utf-8' },
  );
  private credentialsTemplate = fs.readFileSync(
    __dirname + '/templates/credentials.ejs',
    { encoding: 'utf-8' },
  );

  private inAppEmaillTemplate = fs.readFileSync(
    __dirname + '/templates/marketing.ejs',
    { encoding: 'utf-8' },
  );

  constructor(
    @InjectModel(Email.name)
    private emailRepo: Model<Email>,
    private mailerService: MailerService,
  ) {}

  async sendUserConfirmation(data: SendMailDto) {
    const renderedEmail = ejs.render(this.confirmationTemplate, {
      name: data.data['firstName'],
      email: data.data['email'],
      code: data.data['code'],
    });

    return this.mailerService.sendMail({
      to: data.to,
      from: this.from,
      subject: data.subject,
      template: './confirmation',
      context: {
        name: data.data['firstName'],
        email: data.data['email'],
        code: data.data['code'],
      },
      headers: {
        'X-Category': data.type,
      },
      html: renderedEmail,
      text: renderedEmail,
    });
  }

  async sendResetPassword(data: SendMailDto) {
    const renderedEmail = ejs.render(this.resetpasswordTemplate, {
      name: data.data['firstName'],
      url: data.data['url'],
    });

    return this.mailerService.sendMail({
      to: data.to,
      from: this.from,
      subject: data.subject,
      template: './resetpassword',
      html: renderedEmail,
      text: renderedEmail,
      context: {
        name: data.data['firstName'],
        url: data.data['url'],
      },
      headers: {
        'X-Category': data.type,
      },
    });
  }

  async sendUserCredentials(data: SendMailDto) {
    const renderedEmail = ejs.render(this.credentialsTemplate, {
      name: data.data['firstName'],
      email: data.data['email'],
      password: data.data['password'],
    });

    return this.mailerService.sendMail({
      to: data.to,
      from: this.from,
      subject: data.subject,
      template: './credentials',
      context: {
        name: data.data['firstName'],
        email: data.data['email'],
        password: data.data['password'],
      },
      headers: {
        'X-Category': data.type,
      },
      html: renderedEmail,
      text: renderedEmail,
    });
  }

  async sendInAppEmailNotification(data: SendMailDto) {
    const renderedEmail = ejs.render(this.inAppEmaillTemplate, {
      name: data.data['firstName'],
      email: data.data['email'],
      body: data.data['body'],
    });

    return this.mailerService.sendMail({
      to: data.to,
      from: this.from,
      subject: data.subject,
      template: './emailnotification',
      context: {
        name: data.data['firstName'],
        email: data.data['email'],
        body: data.data['body'],
      },
      headers: {
        'X-Category': data.type,
      },
      html: renderedEmail,
      text: renderedEmail,
    });
  }
}
````

## File: src/modules/rides/rides.controller.ts
````typescript
import {
  Controller,
  Post,
  Body,
  UseGuards,
  Logger,
  Get,
  Query,
  Param,
  Patch,
} from '@nestjs/common';
import { RidesService } from './rides.service';
import { CreateRideDto } from './dto/create-ride.dto';
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
import { Ride } from './schemas/ride.schema';
import { SearchRidesDto } from './dto/search-rides.dto';
import { PaginationResultDto } from 'src/core/dto';
import mongoose from 'mongoose';
import { ErrorHelper } from 'src/core/helpers';

@ApiTags('Rides')
@Controller('rides')
export class RidesController {
  private readonly logger = new Logger(RidesController.name);

  constructor(private readonly ridesService: RidesService) {}

  @Post()
  @UseGuards(AuthGuard) // Ensure user is logged in
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Create a new ride offer (Driver only)' })
  @ApiResponse({
    status: 201,
    description: 'Ride created successfully.',
    type: Ride,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid input data.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized - Invalid token.' })
  @ApiResponse({
    status: 403,
    description:
      'Forbidden - User is not a verified driver or vehicle/driver is invalid.',
  })
  @ApiResponse({
    status: 404,
    description: 'Not Found - Driver or Vehicle not found.',
  })
  async createRide(
    @User() driver: IUser, // Get authenticated user (should have DRIVER role)
    @Body() createRideDto: CreateRideDto,
  ): Promise<{ message: string; data: Ride }> {
    // Standard response structure
    this.logger.log(
      `Received request to create ride from driver ID: ${driver._id}`,
    );
    const newRide = await this.ridesService.createRide(
      driver._id,
      createRideDto,
    );
    return {
      message: 'Ride created successfully.',
      data: newRide.toObject() as Ride, // Return plain object
    };
  }

  @Get('/search')
  @UseGuards(AuthGuard) // Require login to search? Or make public? Assuming logged in for now.
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Search for available rides' })
  // Add ApiQuery decorators for Swagger documentation of query parameters
  @ApiQuery({
    name: 'origin[lat]',
    type: Number,
    required: true,
    description: 'Origin latitude',
  })
  @ApiQuery({
    name: 'origin[lon]',
    type: Number,
    required: true,
    description: 'Origin longitude',
  })
  @ApiQuery({
    name: 'destination[lat]',
    type: Number,
    required: true,
    description: 'Destination latitude',
  })
  @ApiQuery({
    name: 'destination[lon]',
    type: Number,
    required: true,
    description: 'Destination longitude',
  })
  @ApiQuery({
    name: 'departureDate',
    type: String,
    required: true,
    example: '2025-08-15',
    description: 'Departure date (YYYY-MM-DD)',
  })
  @ApiQuery({
    name: 'seatsNeeded',
    type: Number,
    required: true,
    example: 1,
    description: 'Number of seats required',
  })
  @ApiQuery({
    name: 'maxDistance',
    type: Number,
    required: false,
    example: 5000,
    description: 'Max search radius in meters',
  })
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
    description: 'List of matching rides found.',
    type: PaginationResultDto<Ride>,
  }) // Hint response type
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid query parameters.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  async searchRides(
    @Query() searchRidesDto: SearchRidesDto, // Use @Query to bind query params to DTO
  ): Promise<PaginationResultDto<Ride>> {
    // Return type matches service
    this.logger.log(
      `Searching rides with criteria: ${JSON.stringify(searchRidesDto)}`,
    );
    // searchRidesDto will have pagination fields inherited
    return await this.ridesService.searchRides(searchRidesDto);
    // TransformInterceptor will format the final response
  }

  // --- New Get Ride By ID Endpoint ---
  @Get(':rideId')
  @UseGuards(AuthGuard) // Or make public if needed
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get details of a specific ride' })
  @ApiResponse({ status: 200, description: 'Ride details found.', type: Ride })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid Ride ID format.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({ status: 404, description: 'Not Found - Ride not found.' })
  async getRideById(
    @Param('rideId') rideId: string,
  ): Promise<{ message: string; data: Ride }> {
    if (!mongoose.Types.ObjectId.isValid(rideId)) {
      ErrorHelper.BadRequestException('Invalid Ride ID format.');
    }
    this.logger.log(`Fetching ride details for ID: ${rideId}`);
    const ride = await this.ridesService.getRideById(rideId);
    return {
      message: 'Ride details fetched successfully.',
      data: ride.toObject() as Ride,
    };
  }

  @Patch(':rideId/start') // New endpoint
  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Start a scheduled ride (Driver only)' })
  @ApiResponse({
    status: 200,
    description: 'Ride started successfully.',
    type: Ride,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Ride cannot be started.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({ status: 403, description: 'Forbidden - Not the driver.' })
  @ApiResponse({ status: 404, description: 'Not Found - Ride not found.' })
  async startRide(
    @User() driver: IUser,
    @Param('rideId') rideId: string,
  ): Promise<{ message: string; data: Ride }> {
    if (!mongoose.Types.ObjectId.isValid(rideId)) {
      ErrorHelper.BadRequestException('Invalid Ride ID format.');
    }
    this.logger.log(`Driver ${driver._id} starting ride ${rideId}`);
    const startedRide = await this.ridesService.startRide(driver._id, rideId);
    return {
      message: 'Ride started successfully.',
      data: startedRide.toObject() as Ride,
    };
  }

  // Endpoint for GET /rides/:rideId/share-link (to be added)
  // Public endpoint GET /trip/:shareToken (to be added in a separate controller/module)
  @Get(':rideId/share-link')
  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Generate a shareable link/token for an in-progress ride',
  })
  @ApiResponse({
    status: 200,
    description: 'Share token generated successfully.',
    schema: {
      properties: {
        shareToken: { type: 'string' },
        expiresAt: { type: 'string', format: 'date-time' },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Ride not in progress.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - User not on this ride.',
  })
  @ApiResponse({ status: 404, description: 'Not Found - Ride not found.' })
  async getShareLink(
    @User() currentUser: IUser,
    @Param('rideId') rideId: string,
  ): Promise<{
    message: string;
    data: { shareToken: string; expiresAt: Date };
  }> {
    if (!mongoose.Types.ObjectId.isValid(rideId)) {
      ErrorHelper.BadRequestException('Invalid Ride ID format.');
    }
    this.logger.log(
      `User ${currentUser._id} requesting share link for ride ${rideId}`,
    );
    const result = await this.ridesService.generateShareLink(
      rideId,
      currentUser._id,
    );
    return {
      message: 'Share link generated successfully.',
      data: result,
    };
  }
}
````

## File: src/modules/twilio/twilio.service.ts
````typescript
import { Injectable, Logger } from '@nestjs/common';
import { Twilio } from 'twilio';
import { SecretsService } from '../../global/secrets/service';
import { error } from 'console';

@Injectable()
export class TwilioService {
  private readonly logger = new Logger(TwilioService.name);
  private twilioClient: Twilio;

  constructor(private secretsService: SecretsService) {
    const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN } =
      this.secretsService.twilio;
    if (TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN) {
      this.twilioClient = new Twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
    } else {
      this.logger.error(
        'Twilio credentials not found. TwilioService will not function.',
      );
      this.logger.debug(error);
    }
  }

  async sendVerificationToken(
    to: string,
    channel: 'sms' | 'call',
  ): Promise<boolean> {
    const { TWILIO_VERIFY_SERVICE_SID } = this.secretsService.twilio;
    if (!this.twilioClient || !TWILIO_VERIFY_SERVICE_SID) {
      this.logger.error('Twilio client or Verify Service SID missing.');
      throw new Error('Verification service is not configured properly.');
    }
    try {
      const verification = await this.twilioClient.verify.v2
        .services(TWILIO_VERIFY_SERVICE_SID)
        .verifications.create({ to, channel });
      this.logger.log(
        `Verification sent to ${to}, Status: ${verification.status}`,
      );
      return verification.status === 'pending';
    } catch (error) {
      this.logger.error(
        `Failed to send verification to ${to}: ${error.message}`,
        error.stack,
      );
      throw new Error(`Failed to send verification code: ${error.message}`);
    }
  }

  async checkVerificationToken(to: string, code: string): Promise<boolean> {
    const { TWILIO_VERIFY_SERVICE_SID } = this.secretsService.twilio;
    if (!this.twilioClient || !TWILIO_VERIFY_SERVICE_SID) {
      this.logger.error('Twilio client or Verify Service SID missing.');
      throw new Error('Verification service is not configured properly.');
    }
    try {
      const verificationCheck = await this.twilioClient.verify.v2
        .services(TWILIO_VERIFY_SERVICE_SID)
        .verificationChecks.create({ to, code });
      this.logger.log(
        `Verification check for ${to}, Status: ${verificationCheck.status}`,
      );
      return verificationCheck.status === 'approved';
    } catch (error) {
      // Twilio might return a 404 for incorrect code, handle gracefully
      if (error.status === 404) {
        this.logger.warn(
          `Verification check failed for ${to}: Incorrect code or expired.`,
        );
        return false;
      }
      this.logger.error(
        `Failed to check verification for ${to}: ${error.message}`,
        error.stack,
      );
      throw new Error(`Failed to verify code: ${error.message}`);
    }
  }
}
````

## File: src/modules/user/schemas/user.schema.ts
````typescript
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { Role } from './role.schema';
import {
  UserGender,
  UserStatus,
  DriverVerificationStatus,
} from 'src/core/enums/user.enum';
import { UserLoginStrategy } from 'src/core/interfaces';
import { Vehicle } from '../../driver/schemas/vehicle.schema';

export type UserDocument = User & Document;

@Schema({ timestamps: true })
export class User {
  @Prop({ type: String, required: true, trim: true })
  firstName: string;

  @Prop({ type: String, required: true, trim: true })
  lastName: string;

  @Prop({
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    index: true,
  })
  email: string;

  @Prop({ type: String, required: false, select: false }) // Required only for LOCAL strategy initially
  password?: string;

  @Prop({ type: String, unique: true, sparse: true, index: true }) // Unique phone number, sparse allows multiple nulls
  phoneNumber?: string;

  @Prop({ type: Boolean, default: false })
  phoneVerified: boolean;

  @Prop({ type: Boolean, default: false })
  emailConfirm: boolean;

  @Prop({ type: String, enum: UserGender })
  gender?: UserGender;

  @Prop({ type: String })
  avatar?: string;

  @Prop({ type: String })
  about?: string;

  @Prop({ type: String })
  country?: string;

  @Prop({
    type: String,
    enum: UserStatus,
    default: UserStatus.PENDING_EMAIL_VERIFICATION,
  })
  status: UserStatus;

  @Prop({
    type: String,
    enum: UserLoginStrategy,
    default: UserLoginStrategy.LOCAL,
  })
  strategy: UserLoginStrategy;

  @Prop({
    type: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Roles' }],
    required: true,
  })
  roles: Role[];

  @Prop({ type: Date })
  lastSeen?: Date;

  // --- Driver Specific Fields (Optional) ---

  @Prop({
    type: String,
    enum: DriverVerificationStatus,
    default: DriverVerificationStatus.NOT_SUBMITTED,
  })
  driverVerificationStatus?: DriverVerificationStatus;

  @Prop({ type: String })
  driverLicenseNumber?: string;

  @Prop({ type: Date })
  driverLicenseExpiry?: Date;

  @Prop({ type: String })
  driverLicenseFrontImageUrl?: string;

  @Prop({ type: String })
  driverLicenseBackImageUrl?: string;

  @Prop({ type: String })
  driverRejectionReason?: string;

  @Prop({ type: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Vehicle' }] })
  vehicles?: Vehicle[];

  // --- Safety & Rating Fields ---

  @Prop({
    type: [
      {
        name: { type: String, required: true },
        phone: { type: String, required: true }, // Add validation for phone format if needed
      },
    ],
    default: [],
    _id: false, // Don't create separate _id for each contact
  })
  emergencyContacts: { name: string; phone: string }[];

  @Prop({ type: Number, default: 0, min: 0, max: 5 })
  averageRatingAsDriver: number;

  @Prop({ type: Number, default: 0, min: 0 })
  totalRatingsAsDriver: number; // Total number of ratings received as driver

  @Prop({ type: Number, default: 0, min: 0, max: 5 })
  averageRatingAsPassenger: number; // Calculated average rating when acting as passenger

  @Prop({ type: Number, default: 0, min: 0 })
  totalRatingsAsPassenger: number; // Total number of ratings received as passenger

  @Prop({ type: [String], default: [], index: true }) // Array to store FCM registration tokens
  deviceTokens: string[];
}

export const UserSchema = SchemaFactory.createForClass(User);
````

## File: src/modules/user/user.module.ts
````typescript
import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { MongooseModule } from '@nestjs/mongoose';
import { Token, TokenSchema } from './schemas/token.schema';
import { UserSchema, User } from './schemas/user.schema';
import { roleSchema, Role } from './schemas/role.schema';
import { UserController } from './user.controller';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Token.name, schema: TokenSchema },
      { name: User.name, schema: UserSchema },
      { name: Role.name, schema: roleSchema },
    ]),
  ],
  providers: [UserService],
  controllers: [UserController],
  exports: [UserService],
})
export class UserModule {}
````

## File: src/modules/user/user.service.ts
````typescript
import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { DateHelper, ErrorHelper } from 'src/core/helpers';
import { IPassenger, IDriver } from 'src/core/interfaces';
import { TokenHelper } from 'src/global/utils/token.utils';
import { UserSessionService } from 'src/global/user-session/service';
import { Token } from './schemas/token.schema';
import { User } from './schemas/user.schema';
import { UpdateEmergencyContactsDto } from './dto/emergency-contact.dto';
import { UserDocument } from './schemas/user.schema';

@Injectable()
export class UserService {
  private logger = new Logger(UserService.name);
  constructor(
    @InjectModel(Token.name) private tokenRepo: Model<Token>,
    private tokenHelper: TokenHelper,
    private userSessionService: UserSessionService,
    @InjectModel(User.name) private userRepo: Model<User>,
  ) {}

  async generateOtpCode(
    user: IDriver | IPassenger,
    options = {
      numberOnly: true,
      length: 4,
    },
    expirationTimeInMinutes = 15,
  ): Promise<string> {
    let code = '';

    if (options.numberOnly) {
      code = this.tokenHelper.generateRandomNumber(options.length);
    } else {
      code = this.tokenHelper.generateRandomString(options.length);
    }

    this.logger.debug('Generating OTP code for user: ', user._id);
    this.logger.debug('OTP code: ', code);

    await this.tokenRepo.findOneAndDelete({ user: user?._id, isUsed: false });

    await this.tokenRepo.create({
      user: user._id,
      code,
      expirationTime: DateHelper.addToCurrent({
        minutes: expirationTimeInMinutes,
      }),
    });

    return code;
  }

  async verifyOtpCode(
    user: IDriver | IPassenger,
    code: string,
    message?: string,
  ): Promise<boolean> {
    const otp = await this.tokenRepo.findOne({
      user: user._id,
      code,
      isUsed: false,
    });

    if (!otp) {
      ErrorHelper.BadRequestException('Invalid code');
    }

    if (DateHelper.isAfter(new Date(), otp.expirationTime)) {
      ErrorHelper.BadRequestException(
        message ||
          "This code has expired. You can't change your password using this link",
      );
    }

    await otp.deleteOne();

    return true;
  }

  async logout(userId: string) {
    await this.userSessionService.delete(userId);

    return {
      success: true,
    };
  }

  async getUser(userId: string): Promise<User> {
    try {
      const user = await this.userRepo.findById(userId);
      if (!user) {
        ErrorHelper.BadRequestException('User does not exists');
      }
      return user;
    } catch (error) {
      ErrorHelper.BadRequestException(error);
    }
  }
  async updateEmergencyContacts(
    userId: string,
    dto: UpdateEmergencyContactsDto,
  ): Promise<UserDocument> {
    this.logger.log(`Updating emergency contacts for user ${userId}`);

    // DTO validation is handled by the ValidationPipe

    try {
      const updatedUser = await this.userRepo.findByIdAndUpdate(
        userId,
        { $set: { emergencyContacts: dto.contacts } }, // Directly set the array
        { new: true, runValidators: true }, // Return updated doc, run schema validation
      );

      if (!updatedUser) {
        ErrorHelper.NotFoundException(`User with ID ${userId} not found.`);
      }

      this.logger.log(`Emergency contacts updated for user ${userId}`);
      // Don't return the full user object usually, maybe just success or limited fields
      return updatedUser; // For now, return updated user
    } catch (error) {
      this.logger.error(
        `Error updating emergency contacts for user ${userId}: ${error.message}`,
        error.stack,
      );
      if (error instanceof NotFoundException) throw error;
      ErrorHelper.InternalServerErrorException(
        'Failed to update emergency contacts.',
      );
    }
  }

  async addDeviceToken(userId: string, deviceToken: string): Promise<boolean> {
    this.logger.log(`Adding device token for user ${userId}`);
    try {
      // Use $addToSet to avoid duplicate tokens for the same user
      const result = await this.userRepo.updateOne(
        { _id: userId },
        { $addToSet: { deviceTokens: deviceToken } },
      );
      this.logger.log(
        `Device token add result for user ${userId}: Modified ${result.modifiedCount}`,
      );
      return result.modifiedCount > 0 || result.matchedCount > 0; // Return true if matched or modified
    } catch (error) {
      this.logger.error(
        `Error adding device token for user ${userId}: ${error.message}`,
        error.stack,
      );
      ErrorHelper.InternalServerErrorException('Failed to register device.');
    }
  }

  async removeDeviceToken(
    userId: string,
    deviceToken: string,
  ): Promise<boolean> {
    this.logger.log(`Removing device token for user ${userId}`);
    try {
      // Use $pull to remove a specific token
      const result = await this.userRepo.updateOne(
        { _id: userId },
        { $pull: { deviceTokens: deviceToken } },
      );
      this.logger.log(
        `Device token remove result for user ${userId}: Modified ${result.modifiedCount}`,
      );
      return result.modifiedCount > 0;
    } catch (error) {
      this.logger.error(
        `Error removing device token for user ${userId}: ${error.message}`,
        error.stack,
      );
      ErrorHelper.InternalServerErrorException('Failed to unregister device.');
    }
  }
}
````

## File: src/modules/app.module.ts
````typescript
import { Module } from '@nestjs/common';
import { AuthGuard } from 'src/core/guards';
import { WsGuard } from 'src/core/guards/ws.guard';
import { AppGateway } from './app.gateway';

@Module({
  providers: [AppGateway, WsGuard, AuthGuard],
  exports: [AuthGuard],
  imports: [],
})
export class AppModule {}
````

## File: test/app.e2e-spec.ts
````typescript
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/modules/main.module';

describe('AppController (e2e)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  it('/ (GET)', () => {
    return request(app.getHttpServer())
      .get('/')
      .expect(200)
      .expect('Hello World!');
  });
});
````

## File: src/core/adpater/redis.adpater.ts
````typescript
import { INestApplication } from '@nestjs/common';
import { IoAdapter } from '@nestjs/platform-socket.io';
import { createAdapter } from '@socket.io/redis-adapter';
import { createClient } from 'redis';
import { Server, ServerOptions } from 'socket.io';
import { SecretsService } from 'src/global/secrets/service';

export class RedisIoAdapter extends IoAdapter {
  protected redisAdapter;

  constructor(app: INestApplication) {
    super();
    const configService = app.get(SecretsService);

    const pubClient = createClient({
      socket: {
        host: configService.userSessionRedis.REDIS_HOST,
        port: parseInt(configService.userSessionRedis.REDIS_PORT, 10),
      },
      username: configService.userSessionRedis.REDIS_USER,
      password: configService.userSessionRedis.REDIS_PASSWORD,
    });
    const subClient = pubClient.duplicate();

    pubClient.connect();
    subClient.connect();

    this.redisAdapter = createAdapter(pubClient, subClient);
  }

  createIOServer(port: number, options?: ServerOptions) {
    const server = super.createIOServer(port, options) as Server;

    server.adapter(this.redisAdapter);

    return server;
  }

  bindClientConnect(server: any, callback: (socket: any) => void): void {
    server.on('connection', (socket: any) => callback(socket));
  }
}
````

## File: src/core/dto/page-meta.dto.ts
````typescript
import { PaginationDto } from './page-options.dto';
import { ApiProperty } from '@nestjs/swagger';

export interface PageMetaDtoParameters {
  pageOptionsDto: PaginationDto;
  itemCount: number;
}

export class PaginationMetadataDto {
  @ApiProperty({
    type: Number,
    description: 'Current page number',
    example: 1,
  })
  readonly page: number;

  @ApiProperty({
    type: Number,
    description: 'Number of items per page',
    example: 10,
  })
  readonly limit: number;

  @ApiProperty({
    type: Number,
    description: 'Total number of items',
    example: 100,
  })
  readonly itemCount: number;

  @ApiProperty({
    type: Number,
    description: 'Total number of pages',
    example: 10,
  })
  readonly pageCount: number;

  @ApiProperty({
    type: Boolean,
    description: 'Whether there is a previous page',
    example: false,
  })
  readonly hasPreviousPage: boolean;

  @ApiProperty({
    type: Boolean,
    description: 'Whether there is a next page',
    example: true,
  })
  readonly hasNextPage: boolean;

  constructor({ pageOptionsDto, itemCount }: PageMetaDtoParameters) {
    this.page = pageOptionsDto.page;
    this.limit = pageOptionsDto.limit;
    this.itemCount = itemCount;
    this.pageCount = Math.ceil(this.itemCount / this.limit);
    this.hasPreviousPage = this.page > 1;
    this.hasNextPage = this.page < this.pageCount;
  }
}
````

## File: src/core/dto/page-options.dto.ts
````typescript
import { Type } from 'class-transformer';
import { IsEnum, IsInt, IsOptional, Min } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export enum Order {
  ASC = 'ASC',
  DESC = 'DESC',
}
export class PaginationDto {
  @ApiProperty({
    enum: Order,
    default: Order.DESC,
    required: false,
    description: 'Order direction (ASC or DESC)',
  })
  @IsEnum(Order)
  @IsOptional()
  readonly order?: Order = Order.DESC;

  @ApiProperty({
    type: Number,
    default: 1,
    required: false,
    description: 'Page number (starts from 1)',
  })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @IsOptional()
  readonly page: number = 1;

  @ApiProperty({
    type: Number,
    default: 10,
    required: false,
    description: 'Number of items per page',
  })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @IsOptional()
  readonly limit: number = 10;

  get skip(): number {
    return (this.page - 1) * this.limit;
  }
}
````

## File: src/core/dto/pagination.dto.ts
````typescript
import { IsArray } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

import { PaginationMetadataDto } from './page-meta.dto';
import { PaginationDto } from './page-options.dto';

export class PaginationResultDto<T> {
  @ApiProperty({
    isArray: true,
    description: 'List of items',
  })
  @IsArray()
  readonly data: T[];

  @ApiProperty({
    type: PaginationMetadataDto,
    description: 'Pagination metadata',
  })
  readonly meta: PaginationMetadataDto;

  constructor(
    data: T[],
    itemCount: number,
    options: {
      page: number;
      limit: number;
    },
  ) {
    this.data = data;
    this.meta = new PaginationMetadataDto({
      itemCount,
      pageOptionsDto: options as PaginationDto,
    });
  }
}
````

## File: src/core/guards/index.ts
````typescript
export * from './authenticate.guard';
export * from './ws.guard';
export * from './role.guards';
````

## File: src/core/interfaces/user/index.ts
````typescript
export * from './user.interface';
export * from './role.interface';
````

## File: src/core/interfaces/user/user.interface.ts
````typescript
/* eslint-disable @typescript-eslint/no-explicit-any */
import { Types } from 'mongoose';
import { UserGender } from 'src/core/enums/user.enum';
import { UserStatus } from 'src/core/enums/user.enum';
import { Role } from 'src/modules/user/schemas/role.schema';

export interface IUser {
  _id?: string;
  firstName: string;
  lastName: string;
  email: string;
  reasonToJoin?: string;
  profession?: string;
  pathway?: string;
  techStacks?: object;
  assessmentScore?: string;
  emailConfirm: boolean;
  createdAt?: Date;
  lastSeen?: Date;
  status?: UserStatus;
  roles?: Types.ObjectId[] | Role[]; // Array of ObjectId or string
}

export interface IUser {
  _id?: string;
  email: string;
  firstName: string;
  lastName: string;
  avatar?: string;
  about?: string;
  country?: string;
  gender?: UserGender;
  phoneNumber?: string;
  emailConfirm: boolean;
  createdAt?: Date;
  lastSeen?: Date;
  status?: UserStatus;
}

export interface IDriver {
  _id?: string;
  email: string;
  firstName: string;
  lastName: string;
  avatar?: string;
  about?: string;
  country?: string;
  gender?: UserGender;
  phoneNumber?: string;
  emailConfirm: boolean;
  createdAt?: Date;
  lastSeen?: Date;
  status?: UserStatus;
}

export interface IPassenger {
  _id?: string;
  email: string;
  firstName: string;
  lastName: string;
  avatar?: string;
  about?: string;
  country?: string;
  gender?: UserGender;
  phoneNumber?: string;
  emailConfirm: boolean;
  createdAt?: Date;
  lastSeen?: Date;
  status?: UserStatus;
}

export interface IAdmin {
  _id?: string;
  email: string;
  firstName: string;
  lastName: string;
  avatar?: string;
  about?: string;
  country?: string;
  gender?: UserGender;
  phoneNumber?: string;
  emailConfirm: boolean;
  createdAt?: Date;
  lastSeen?: Date;
  status?: UserStatus;
}

export interface IUserMail {
  email: string;
  firstName: string;
}

export enum UserLoginStrategy {
  LOCAL = 'local',
  GOOGLE = 'google',
  FACEBOOK = 'facebook',
  APPLE = 'apple',
}
````

## File: src/core/interfaces/index.ts
````typescript
export * from './http';
export * from './user';

export type envType =
  | 'development'
  | 'production'
  | 'test'
  | 'stg'
  | 'dev'
  | 'prod'
  | 'develop';
````

## File: src/global/user-session/module.ts
````typescript
import { Module } from '@nestjs/common';
import { RedisModule } from '@nestjs-modules/ioredis';

import { SecretsService } from '../secrets/service';
import { UserSessionService } from './service';

@Module({
  imports: [
    RedisModule.forRootAsync({
      useFactory: ({ userSessionRedis }: SecretsService) => {
        if (!userSessionRedis.REDIS_HOST) {
          throw new Error(
            'Invalid Redis configuration: REDIS_HOST is missing.',
          );
        }
        return {
          type: 'single',
          url: `redis://${userSessionRedis.REDIS_USER}:${userSessionRedis.REDIS_PASSWORD}@${userSessionRedis.REDIS_HOST}:${userSessionRedis.REDIS_PORT}`,
        };
      },
      inject: [SecretsService],
    }),
  ],
  providers: [UserSessionService],
  exports: [UserSessionService],
})
export class UserSessionModule {}
````

## File: src/modules/auth/dto/base-registeration.dto.ts
````typescript
import { Transform } from 'class-transformer';
import {
  IsEmail,
  IsEnum,
  IsNotEmpty,
  IsOptional,
  IsString,
  MinLength,
  IsBoolean,
  Equals,
  IsPhoneNumber,
} from 'class-validator';
import { PASSWORD_PATTERN } from '../../../core/constants/base.constant';
import { UserGender } from 'src/core/enums/user.enum';
import { IsMatchPattern } from '../../../core/validators/IsMatchPattern.validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class BaseRegistrationDto {
  @ApiProperty({ description: "User's first name", minLength: 2 })
  @IsString()
  @IsNotEmpty()
  @MinLength(2)
  firstName: string;

  @ApiProperty({ description: "User's last name", minLength: 2 })
  @IsString()
  @IsNotEmpty()
  @MinLength(2)
  lastName: string;

  @ApiProperty({ description: "User's email address" })
  @IsEmail()
  @IsNotEmpty()
  @Transform(({ value }) => value?.toLowerCase().trim())
  email: string;

  @ApiProperty({
    description:
      "User's password - must contain uppercase, lowercase, and number",
    minLength: 8,
    pattern: PASSWORD_PATTERN,
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @IsMatchPattern(PASSWORD_PATTERN, {
    message:
      'Password must contain at least one uppercase letter, one lowercase letter, and one number',
  })
  password: string;

  @ApiPropertyOptional({
    description: 'Nigerian phone number',
    example: '+2348012345678',
  })
  @IsOptional()
  @IsPhoneNumber('NG', {
    message: 'Please provide a valid Nigerian phone number',
  })
  phoneNumber?: string;

  @ApiPropertyOptional({ description: "User's country" })
  @IsOptional()
  @IsString()
  country?: string;

  @ApiPropertyOptional({
    description: "User's gender",
    enum: UserGender,
  })
  @IsOptional()
  @IsEnum(UserGender)
  gender?: UserGender;

  @ApiProperty({
    description: 'Whether user has accepted terms and conditions',
    default: false,
  })
  @IsBoolean({ message: 'You must accept the terms and conditions.' })
  @Equals(true, { message: 'You must accept the terms and conditions.' })
  termsAccepted: boolean;
}
````

## File: src/modules/auth/dto/update-user.dto.ts
````typescript
import { IsOptional, IsString } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class UpdateUserDto {
  @ApiPropertyOptional({
    description: 'Updated first name',
    minLength: 2,
  })
  @IsOptional()
  @IsString()
  firstName?: string;

  @ApiPropertyOptional({
    description: 'Updated last name',
    minLength: 2,
  })
  @IsOptional()
  @IsString()
  lastName?: string;

  @ApiPropertyOptional({ description: 'Updated about section' })
  @IsOptional()
  @IsString()
  about?: string;

  @ApiPropertyOptional({
    description: 'Updated email address',
    example: 'user@example.com',
  })
  @IsOptional()
  @IsString()
  email?: string;
}
````

## File: src/modules/auth/auth.module.ts
````typescript
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { EncryptHelper } from 'src/core/helpers';
import { TokenHelper } from 'src/global/utils/token.utils';
import { MailController } from '../mail/mail.controller';
import { MailEvent } from '../mail/mail.event';
import { MongooseModule } from '@nestjs/mongoose';
import { TokenSchema, Token } from '../user/schemas/token.schema';
import { MailModule } from '../mail/mail.module';
import { UserModule } from '../user/user.module';
import { roleSchema, Role } from '../user/schemas/role.schema';
import { AwsS3Module } from '../storage';
import { UserSchema, User } from '../user/schemas/user.schema';
import { TwilioModule } from '../twilio/twiio.module';

@Module({
  imports: [
    MailModule,
    UserModule,
    TwilioModule,
    MongooseModule.forFeature([
      { name: Token.name, schema: TokenSchema },
      { name: Role.name, schema: roleSchema },
      { name: User.name, schema: UserSchema },
    ]),
    AwsS3Module.forRoot('authAwsSecret'),
  ],
  providers: [
    AuthService,
    TokenHelper,
    EncryptHelper,
    MailEvent,
    MailController,
  ],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule {}
````

## File: src/modules/health/health.controller.ts
````typescript
import { Controller, Get, Res } from '@nestjs/common';
import {
  HealthCheck,
  HealthCheckService,
  MongooseHealthIndicator,
} from '@nestjs/terminus';
import { Response } from 'express';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';

@ApiTags('Health')
@Controller('/health-check')
export class HealthController {
  constructor(
    private health: HealthCheckService,
    private mongo: MongooseHealthIndicator,
  ) {}

  @Get()
  @HealthCheck()
  @ApiOperation({ summary: 'Check API health status' })
  @ApiResponse({
    status: 200,
    description: 'API is healthy',
    schema: {
      type: 'object',
      properties: {
        status: { type: 'number', example: 200 },
        healthInfo: {
          type: 'object',
          properties: {
            status: { type: 'string', example: 'ok' },
            info: { type: 'object' },
            error: { type: 'object' },
            details: { type: 'object' },
          },
        },
      },
    },
  })
  @ApiResponse({ status: 503, description: 'API is not healthy' })
  async check(@Res() res: Response) {
    try {
      const healthInfo = await this.health.check([
        () => this.mongo.pingCheck('mongodb', { timeout: 3000 }),
      ]);
      return res.status(200).json({ status: 200, healthInfo });
    } catch (error) {
      return res.status(503).send(error);
    }
  }
}
````

## File: src/modules/mail/mail.controller.ts
````typescript
import { Controller, Logger, Post } from '@nestjs/common';
import { SendMailDto } from './dto/mail.dto';
import { MailService } from './mail.service';
import { MailType } from './enums';

@Controller()
export class MailController {
  private logger = new Logger(MailController.name);

  constructor(private readonly mailService: MailService) {}

  @Post('mail')
  async sendMail(data: SendMailDto) {
    this.logger.log('sendMail event received', JSON.stringify(data));

    try {
      switch (data.type) {
        case MailType.USER_CONFIRMATION:
          await this.mailService.sendUserConfirmation(data);
          this.logger.log('sendUserConfirmation called');
          break;

        case MailType.USER_CREDENTIALS:
          await this.mailService.sendUserCredentials(data);
          this.logger.log('sendUserCredentials called');
          break;

        case MailType.RESET_PASSWORD:
          await this.mailService.sendResetPassword(data);
          this.logger.log('sendResetPassword called');
          break;

        case MailType.IN_APP_EMAIL:
          await this.mailService.sendInAppEmailNotification(data);
          this.logger.log('sendInAppEmailNotification called');
          break;

        default:
          break;
      }
    } catch (error) {
      this.logger.error(error);
    }
  }
}
````

## File: src/modules/rides/rides.module.ts
````typescript
import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { RidesService } from './rides.service';
import { RidesController } from './rides.controller';
import { Ride, RideSchema } from './schemas/ride.schema';
import { Vehicle, VehicleSchema } from '../driver/schemas/vehicle.schema'; // Need VehicleModel
import { User, UserSchema } from '../user/schemas/user.schema'; // Need UserModel
import { GeolocationModule } from '../geolocation/geolocation.module';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Ride.name, schema: RideSchema },
      { name: Vehicle.name, schema: VehicleSchema }, // Provide VehicleModel
      { name: User.name, schema: UserSchema }, // Provide UserModel
    ]),
    GeolocationModule,
  ],
  providers: [RidesService],
  controllers: [RidesController],
  exports: [RidesService], // Export if needed
})
export class RidesModule {}
````

## File: src/modules/rides/rides.service.ts
````typescript
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
import { BookingStatus } from '../booking/enums/booking-status.enum';
import { PopulatedRideWithBookings } from './interfaces/populated-ride.interface';

@Injectable()
export class RidesService {
  private readonly logger = new Logger(RidesService.name);

  constructor(
    @InjectModel(Ride.name) private rideModel: Model<RideDocument>,
    @InjectModel(Vehicle.name) private vehicleModel: Model<VehicleDocument>,
    @InjectModel(User.name) private userModel: Model<UserDocument>,
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
    // Optional: Check if departure time is reasonably close

    // 2. Update Status
    ride.status = RideStatus.IN_PROGRESS;
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
}
````

## File: nest-cli.json
````json
{
  "$schema": "https://json.schemastore.org/nest-cli",
  "collection": "@nestjs/schematics",
  "sourceRoot": "src",
  "compilerOptions": {
    "deleteOutDir": true,
    "assets": [
      {
        "include": "modules/mail/templates/**/*",
        "outDir": "dist"
      }
    ]
  }
}
````

## File: src/modules/auth/dto/auth.dto.ts
````typescript
import {
  IsBoolean,
  IsEmail,
  IsEnum,
  IsOptional,
  IsString,
  IsUrl,
} from 'class-validator';
import { PortalType } from 'src/core/enums/auth.enum';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class EmailConfirmationDto {
  @ApiProperty({ description: 'Email verification code' })
  @IsString()
  code: string;
}

export class TCodeLoginDto {
  @ApiProperty({ description: 'Temporary authentication code' })
  @IsString()
  tCode: string;

  @ApiProperty({
    description: 'Type of portal user is accessing',
    enum: PortalType,
  })
  @IsString()
  portalType: PortalType;
}

export class CallbackURLDto {
  @ApiPropertyOptional({
    description: 'URL to redirect after action',
    required: false,
  })
  @IsUrl({ require_tld: false })
  @IsOptional()
  callbackURL: string;
}

export class RefreshTokenDto {
  @ApiProperty({ description: 'Refresh token for getting new access token' })
  @IsString()
  token: string;
}

export class ForgotPasswordDto {
  @ApiProperty({
    description: 'Email address for password reset',
    example: 'user@example.com',
  })
  @IsString()
  @IsEmail()
  email: string;
}

export class LoginDto {
  @ApiProperty({
    description: "User's email address",
    example: 'user@example.com',
  })
  @IsString()
  @IsEmail()
  email: string;

  @ApiProperty({ description: "User's password" })
  @IsString()
  password: string;

  @ApiProperty({
    description: 'Type of portal user is accessing',
    enum: PortalType,
  })
  @IsEnum(PortalType)
  portalType: PortalType;

  @ApiPropertyOptional({
    description: 'Whether to keep user logged in',
    default: false,
  })
  @IsOptional()
  @IsBoolean()
  rememberMe = false;
}
````

## File: src/main.ts
````typescript
import { NestFactory } from '@nestjs/core';
import * as express from 'express';
import { MainModule } from './modules/main.module';
import { SecretsService } from './global/secrets/service';
import * as cookieParser from 'cookie-parser';
import { ValidationPipe } from '@nestjs/common';
import { HttpExceptionFilter } from './core/filters';
import { LoggerInterceptor, TransformInterceptor } from './core/interceptors';
import { MongooseModule } from '@nestjs/mongoose';
import { RedisIoAdapter } from './core/adpater';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(MainModule, {
    bufferLogs: true,
    cors: true,
  });

  const { PORT, MONGO_URI } = app.get<SecretsService>(SecretsService);

  app.use(cookieParser());
  app.use(
    (
      req: express.Request,
      res: express.Response,
      next: express.NextFunction,
    ): void => {
      if (req.originalUrl.includes('/webhook')) {
        express.raw({ type: 'application/json' })(req, res, next);
      } else {
        express.json()(req, res, next);
      }
    },
  );

  app.useGlobalPipes(new ValidationPipe());
  app.useGlobalFilters(new HttpExceptionFilter());
  app.useGlobalInterceptors(
    new LoggerInterceptor(),
    new TransformInterceptor(),
  );

  MongooseModule.forRoot(MONGO_URI);

  app.setGlobalPrefix('api');
  app.useWebSocketAdapter(new RedisIoAdapter(app));

  // Setup Swagger
  const config = new DocumentBuilder()
    .setTitle('TavEazi API')
    .setDescription('The TravEazi API documentation')
    .setVersion('1.0')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  await app.listen(PORT);
}
bootstrap();
````

## File: src/global/secrets/service.ts
````typescript
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class SecretsService extends ConfigService {
  private readonly logger = new Logger(SecretsService.name);
  constructor() {
    super();
  }

  NODE_ENV = this.get<string>('NODE_ENV');
  PORT = this.get('PORT');
  MONGO_URI = this.get('MONGO_URI');

  get mailSecret() {
    return {
      MAIL_USERNAME: this.get('MAIL_USERNAME'),
      MAIL_PASSWORD: this.get('MAIL_PASSWORD'),
      MAIL_HOST: this.get('MAIL_HOST'),
      MAIL_PORT: this.get('MAIL_PORT'),
      SENDER_EMAIL: this.get<string>('SENDER_EMAIL', ''),
      NAME: this.get<string>('NAME', ''),
    };
  }

  get googleSecret() {
    return {
      GOOGLE_CLIENT_ID: this.get('GOOGLE_CLIENT_ID'),
      GOOGLE_CLIENT_SECRET: this.get('GOOGLE_CLIENT_SECRET'),
    };
  }

  get jwtSecret() {
    return {
      JWT_SECRET: this.get('APP_SECRET'),
      JWT_EXPIRES_IN: this.get('ACCESS_TOKEN_EXPIRES', '14d'),
    };
  }

  get database() {
    return {
      host: this.get('MONGO_HOST'),
      user: this.get('MONGO_ROOT_USERNAME'),
      pass: this.get('MONGO_ROOT_PASSWORD'),
    };
  }

  get userSessionRedis() {
    return {
      REDIS_HOST: this.get('REDIS_HOST'),
      REDIS_USER: this.get('REDIS_USERNAME'),
      REDIS_PASSWORD: this.get('REDIS_PASSWORD'),
      REDIS_PORT: this.get('REDIS_PORT'),
    };
  }

  get authAwsSecret() {
    return {
      AWS_REGION: this.get('AWS_REGION', 'eu-west-2'),
      AWS_ACCESS_KEY_ID: this.get('AWS_ACCESS_KEY_ID', 'AKIA36G3JG4TMYVGM6G2'),
      AWS_SECRET_ACCESS_KEY: this.get(
        'AWS_SECRET_ACCESS_KEY',
        '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',
      ),
      AWS_S3_BUCKET_NAME: this.get('AWS_S3_BUCKET_NAME', 'traveazi-prod-sess'),
    };
  }

  get twilio() {
    return {
      TWILIO_ACCOUNT_SID: this.get('TWILIO_ACCOUNT_SID'),
      TWILIO_AUTH_TOKEN: this.get('TWILIO_AUTH_TOKEN'),
      TWILIO_PHONE_NUMBER: this.get('TWILIO_PHONE_NUMBER'),
      TWILIO_VERIFY_SERVICE_SID: this.get('TWILIO_VERIFY_SERVICE_SID'),
    };
  }

  get paystack() {
    const secretKey = this.get<string>('PAYSTACK_SECRET_KEY');
    const publicKey = this.get<string>('PAYSTACK_PUBLIC_KEY');
    const baseUrl = this.get<string>(
      'PAYSTACK_BASE_URL',
      'https://api.paystack.co',
    );
    const frontendCallbackUrl = this.get<string>(
      'FRONTEND_PAYMENT_CALLBACK_URL',
    );

    if (!secretKey || !publicKey) {
      this.logger.error(
        'Paystack Secret Key or Public Key missing in .env configuration!',
      );
    }
    if (!frontendCallbackUrl) {
      this.logger.warn(
        'FRONTEND_PAYMENT_CALLBACK_URL not set in .env, Paystack callback might not work as expected.',
      );
    }

    return {
      secretKey,
      publicKey,
      baseUrl,
      frontendCallbackUrl, // URL where frontend handles Paystack redirect
    };
  }

  get googleMaps() {
    const apiKey = this.get<string>('GOOGLE_MAPS_API_KEY');
    if (!apiKey) {
      this.logger.error(
        'GOOGLE_MAPS_API_KEY is missing in .env configuration!',
      );
    }
    return { apiKey };
  }

  get firebase() {
    const serviceAccountPath = this.get<string>(
      'FIREBASE_SERVICE_ACCOUNT_PATH',
    );
    if (!serviceAccountPath) {
      this.logger.error(
        'FIREBASE_SERVICE_ACCOUNT_PATH is missing in .env configuration!',
      );
    }
    return { serviceAccountPath };
  }
}
````

## File: src/modules/main.module.ts
````typescript
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { DatabaseModule } from './database/database.module';
import { RidesModule } from './rides/rides.module';
import { GeolocationModule } from './geolocation/geolocation.module';
import { DriverModule } from './driver/driver.module';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { MongooseModule } from '@nestjs/mongoose';
import { SecretsModule } from '../global/secrets/module';
import { SecretsService } from '../global/secrets/service';
import { AppModule } from './app.module';
import { GlobalModule } from 'src/global/global.module';
import { BookingModule } from './booking/booking.module';
import { RatingModule } from './rating/rating.module';
import { CommunicationModule } from './communication/communication.module';
import { AdminModule } from './admin/admin.module';
import { TripSharingModule } from './trip-sharing/trip-sharing.module';
import { NotificationModule } from './notification/notification.module';
@Module({
  imports: [
    GlobalModule,
    DatabaseModule,
    ConfigModule,
    AuthModule,
    UserModule,
    RidesModule,
    DriverModule,
    GeolocationModule,
    AppModule,
    BookingModule,
    RatingModule,
    CommunicationModule,
    AdminModule,
    UserModule,
    TripSharingModule,
    NotificationModule,
    MongooseModule.forRootAsync({
      imports: [SecretsModule],
      inject: [SecretsService],
      useFactory: (secretsService: SecretsService) => ({
        uri: secretsService.MONGO_URI,
      }),
    }),
  ],
  controllers: [],
  providers: [],
})
export class MainModule {}
````

## File: src/modules/auth/auth.service.ts
````typescript
import { Injectable, Logger } from '@nestjs/common';
import {
  EMAIL_ALREADY_EXISTS,
  INVALID_CODE,
  INVALID_CODE_FORGOT_PASSWORD,
  INVALID_EMAIL_OR_PASSWORD,
  INVALID_USER,
  PORTAL_TYPE_ERROR,
} from 'src/core/constants/messages.constant';
import { EncryptHelper, ErrorHelper } from 'src/core/helpers';
import { UserLoginStrategy, IDriver, IPassenger } from 'src/core/interfaces';
import { PassengerRegistrationDto } from '../passenger/dto/passenger.dto';
import { DriverRegistrationDto } from '../driver/dto/driver-registration.dto';
import { UserService } from '../user/user.service';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Token } from '../user/schemas/token.schema';
import { MailEvent } from '../mail/mail.event';
import { UserSessionService } from 'src/global/user-session/service';
import { TokenHelper } from 'src/global/utils/token.utils';
import { PortalType } from 'src/core/enums/auth.enum';
import { UpdateUserDto } from './dto/update-user.dto';
import { AwsS3Service } from '../storage';
import { Role } from '../user/schemas/role.schema';
import { User } from '../user/schemas/user.schema';
import { IUser } from 'src/core/interfaces';
import { LoginDto } from './dto/auth.dto';
import { UserStatus } from 'src/core/enums/user.enum';
import { TwilioService } from '../twilio/twilio.service';
import { SendPhoneOtpDto, VerifyPhoneOtpDto } from './dto/send-phone-otp.dto';

@Injectable()
export class AuthService {
  private logger = new Logger(AuthService.name);

  constructor(
    @InjectModel(Token.name) private tokenRepo: Model<Token>,
    @InjectModel(Role.name) private roleRepo: Model<Role>,
    @InjectModel(User.name) private userRepo: Model<User>,
    private userService: UserService,
    private mailEvent: MailEvent,
    private encryptHelper: EncryptHelper,
    private tokenHelper: TokenHelper,
    private userSessionService: UserSessionService,
    private awsS3Service: AwsS3Service,
    private twilioService: TwilioService,
  ) {}

  async sendPhoneVerificationOtp(
    dto: SendPhoneOtpDto,
  ): Promise<{ message: string }> {
    const { phoneNumber } = dto;

    // 1. Check if phone number is already registered and verified (optional but recommended)
    const existingUser = await this.userRepo.findOne({
      phoneNumber,
      phoneVerified: true,
    });
    if (existingUser) {
      ErrorHelper.ConflictException(
        'This phone number is already associated with a verified account.',
      );
    }

    // 2. Send verification via Twilio Verify
    try {
      const sent = await this.twilioService.sendVerificationToken(
        phoneNumber,
        'sms',
      );
      if (sent) {
        return { message: 'Verification code sent successfully via SMS.' };
      } else {
        // Should not happen if sendVerificationToken throws on failure, but as fallback
        ErrorHelper.InternalServerErrorException(
          'Could not send verification code.',
        );
      }
    } catch (error) {
      // Error is already logged in TwilioService, rethrow specific message
      ErrorHelper.InternalServerErrorException(
        error.message || 'Could not send verification code.',
      );
    }
  }

  async verifyPhoneNumberOtp(
    dto: VerifyPhoneOtpDto,
  ): Promise<{ verified: boolean; message: string }> {
    const { phoneNumber, otp } = dto;

    // 1. Check verification using Twilio Verify
    try {
      const isApproved = await this.twilioService.checkVerificationToken(
        phoneNumber,
        otp,
      );

      if (isApproved) {
        // Optionally: If you want to mark the number as pre-verified for registration,
        // you could store a temporary flag in Redis associated with the phone number.
        // Example: await this.redisClient.set(`preverified:${phoneNumber}`, 'true', 'EX', 600); // 10 min expiry

        return {
          verified: true,
          message: 'Phone number verified successfully.',
        };
      } else {
        // checkVerificationToken returned false (invalid/expired code)
        ErrorHelper.BadRequestException(
          'Invalid or expired verification code.',
        );
      }
    } catch (error) {
      // Error is already logged in TwilioService, rethrow specific message
      ErrorHelper.InternalServerErrorException(
        error.message || 'Could not verify code.',
      );
    }
  }

  async createPortalUser(
    payload: DriverRegistrationDto | PassengerRegistrationDto,
    portalType: PortalType,
  ): Promise<any> {
    try {
      const user = await this.createUser(payload, {
        strategy: UserLoginStrategy.LOCAL,
        portalType,
      });

      const tokenInfo = await this.generateUserSession(user);

      return {
        token: tokenInfo,
        user: user,
      };
    } catch (error) {
      ErrorHelper.ConflictException('Email Already Exist');
      this.logger.log('createPortalUser', { error });
    }
  }

  private async generateUserSession(
    user: IDriver | IPassenger,
    rememberMe = true,
  ) {
    const tokenInfo = this.tokenHelper.generate(user);

    await this.userSessionService.create(user, {
      sessionId: tokenInfo.sessionId,
      rememberMe,
    });

    return tokenInfo;
  }

  async createUser(
    payload: DriverRegistrationDto | PassengerRegistrationDto,
    options: {
      strategy: UserLoginStrategy;
      portalType: PortalType;
      adminCreated?: boolean;
    },
  ): Promise<IPassenger | IDriver> {
    const { email, phoneNumber } = payload;
    const { strategy, portalType } = options;

    const emailQuery = {
      email: email.toLowerCase(),
    };

    if (!portalType) {
      ErrorHelper.BadRequestException(PORTAL_TYPE_ERROR);
    }

    const emailExist = await this.userRepo.findOne(emailQuery, {
      getDeleted: true,
    });

    if (emailExist) {
      ErrorHelper.BadRequestException(EMAIL_ALREADY_EXISTS);
    }

    //  let phoneVerifiedStatus = false;
    if (phoneNumber) {
      const phoneExist = await this.userRepo.findOne({
        phoneNumber: phoneNumber,
      });
      if (phoneExist?.phoneVerified) {
        ErrorHelper.ConflictException(
          'Phone number already linked to a verified account.',
        );
      }
    }

    const roleData = await this.roleRepo.findOne({ name: portalType });

    const user = await this.userRepo.create({
      email: payload.email.toLowerCase(),
      password: await this.encryptHelper.hash(payload.password),
      firstName: payload.firstName,
      lastName: payload.lastName,
      country: payload.country,
      strategy,
      emailConfirm: strategy === UserLoginStrategy.LOCAL ? false : true,
      portalType: portalType,
      roles: [roleData],
    });

    return { ...user.toObject(), _id: user._id.toString() };
  }

  async login(params: LoginDto) {
    try {
      const { email, password, portalType } = params;

      const user = await this.validateUser(email, password, portalType);

      const tokenInfo = await this.generateUserSession(user, params.rememberMe);

      await this.userRepo.updateOne(
        { _id: user._id },
        { lastSeen: new Date() },
      );

      return {
        token: tokenInfo,
        user,
      };
    } catch (error) {
      ErrorHelper.BadRequestException(error);
    }
  }

  async validateUser(
    email: string,
    password: string,
    portalType?: PortalType,
  ): Promise<IDriver | IPassenger> {
    const emailQuery = {
      email: email.toLowerCase(),
    };

    const user = await this.userRepo
      .findOne(emailQuery)
      .populate('roles', 'name');

    if (!user) {
      ErrorHelper.BadRequestException(INVALID_EMAIL_OR_PASSWORD);
    }

    const passwordMatch = await this.encryptHelper.compare(
      password,
      user.password,
    );
    if (!passwordMatch) {
      ErrorHelper.BadRequestException(INVALID_EMAIL_OR_PASSWORD);
    }

    if (user.status === UserStatus.INACTIVE) {
      ErrorHelper.BadRequestException('Your account is inactive');
    }

    const roleNames = user.roles.map((role) => role.name);

    if (!roleNames.includes(portalType as any)) {
      ErrorHelper.ForbiddenException(
        'Forbidden: You does not have the required role to access this route.',
      );
    }

    return { ...user.toObject(), _id: user._id.toString() };
  }

  async resendVerificationEmail(userId: string) {
    const user = await this.userRepo.findById(userId);

    if (!user) {
      ErrorHelper.BadRequestException('User not found');
    }

    if (user.emailConfirm) {
      ErrorHelper.BadRequestException('Email already confirmed');
    }

    const confirmationCode = await this.userService.generateOtpCode({
      ...user.toObject(),
      _id: user._id.toString(),
    });

    await this.mailEvent.sendUserConfirmation(user, confirmationCode);

    return user;
  }

  async forgotPassword(email: string, callbackURL: string) {
    const emailQuery = {
      email: email.toLowerCase(),
    };

    if (!callbackURL) {
      ErrorHelper.BadRequestException('Please input a valid callbackURL');
    }

    const user = await this.userRepo.findOne(emailQuery);

    if (!user) {
      ErrorHelper.BadRequestException('User does not exist');
    }

    const confirmationCode = await this.userService.generateOtpCode(
      { ...user.toObject(), _id: user._id.toString() },
      {
        numberOnly: false,
        length: 21,
      },
    );

    await this.mailEvent.sendResetPassword(user, confirmationCode, callbackURL);

    return {
      success: true,
    };
  }

  async resetPassword(code: string, password: string) {
    const token = await this.tokenRepo.findOne({ code });

    if (!token) {
      ErrorHelper.BadRequestException(INVALID_CODE_FORGOT_PASSWORD);
    }

    const user = await this.userRepo.findById(token.user);

    if (!user) {
      ErrorHelper.BadRequestException(INVALID_USER);
    }

    // Ensure new password is not the same as the old password
    const passwordMatch = await this.encryptHelper.compare(
      password,
      user.password,
    );
    if (passwordMatch) {
      ErrorHelper.BadRequestException(
        'New password cannot be the same as the previous password',
      );
    }

    await this.userService.verifyOtpCode(
      { ...user.toObject(), _id: user._id.toString() },
      code,
    );

    const hashedPassword = await this.encryptHelper.hash(password);

    await this.userRepo.findByIdAndUpdate(user._id, {
      password: hashedPassword,
      hasChangedPassword: true, // Mark password as changed
    });

    return {
      success: true,
    };
  }

  async verifyUserEmail(userId: string, code: string) {
    const errorMessage = 'OTP has expired';

    const user = await this.userRepo.findById(userId);

    if (!user) {
      ErrorHelper.BadRequestException('User not found');
    }

    await this.userService.verifyOtpCode(
      { ...user.toObject(), _id: user._id.toString() },
      code,
      errorMessage,
    );

    const updatedUser = await this.userRepo.findByIdAndUpdate(
      user._id,
      { emailConfirm: true },
      { new: true },
    );

    return updatedUser;
  }

  async logoutUser(userId: string) {
    return await this.userService.logout(userId);
  }

  async tCodeLogin(code: string) {
    const token = await this.tokenRepo.findOne({ code });

    if (!token) {
      ErrorHelper.BadRequestException(INVALID_CODE);
    }

    let user = null;

    user = await this.userRepo.findById(token.user);

    if (!user) {
      ErrorHelper.BadRequestException(INVALID_USER);
    }

    await this.userService.verifyOtpCode(user.toObject(), code);
    const tokenInfo = await this.generateUserSession(user.toObject());

    return {
      token: tokenInfo,
      user: user.toObject(),
    };
  }

  async getAllUsers() {
    return await this.userRepo.find({});
  }

  async getUserInfo(email: string): Promise<IUser> {
    const user = await this.userRepo.findOne({ email });

    if (!user) {
      ErrorHelper.NotFoundException('No User Found.');
    }

    return { ...user.toJSON(), _id: user._id.toString() };
  }

  async updateUserInfo(
    userId: string,
    updateUserDto: UpdateUserDto,
  ): Promise<IDriver | IPassenger> {
    const updatedUser = await this.userRepo.findByIdAndUpdate(
      userId,
      { $set: updateUserDto },
      { new: true, runValidators: true },
    );

    if (!updatedUser) {
      ErrorHelper.NotFoundException(INVALID_USER);
    }

    return { ...updatedUser.toObject(), _id: updatedUser._id.toString() };
  }

  async uploadAvatar(userId: string, file: Express.Multer.File) {
    const user = await this.userRepo.findById(userId);

    if (!user) {
      ErrorHelper.NotFoundException('User not found');
    }

    if (!file) {
      ErrorHelper.BadRequestException('Image is required');
    }

    const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (!allowedMimeTypes.includes(file.mimetype)) {
      ErrorHelper.BadRequestException(
        'Unsupported file type. Please upload a JPEG, PNG, or GIF image.',
      );
    }

    const maxSizeInBytes = 5 * 1024 * 1024; // 5 MB
    if (file.size > maxSizeInBytes) {
      ErrorHelper.BadRequestException(
        'File size exceeds the maximum limit of 5 MB.',
      );
    }

    const uploadedUrl = await this.awsS3Service.uploadAttachment(file);

    await this.userRepo.findByIdAndUpdate(userId, { avatar: uploadedUrl });

    return { avatar: uploadedUrl };
  }

  async changePasswordConfirmation(
    user: IPassenger | IDriver,
    oldPassword: string,
  ) {
    const _user = await this.userRepo.findById(user._id);

    if (_user.strategy !== UserLoginStrategy.LOCAL && !_user.password) {
      ErrorHelper.ForbiddenException(
        'You can not change your password since you do not have one, please use the forgot password to get a password',
      );
    }

    const passwordMatch = await this.encryptHelper.compare(
      oldPassword,
      _user.password,
    );

    if (!passwordMatch) {
      ErrorHelper.BadRequestException('Please enter a valid current password');
    }

    const confirmationCode = await this.userService.generateOtpCode(user);

    await this.mailEvent.sendUserConfirmation(
      user as IDriver | IPassenger,
      confirmationCode,
    );

    return {
      success: true,
    };
  }

  async verifychangePasswordConfirmation(
    user: IDriver | IPassenger,
    code: string,
  ) {
    const errorMessage = 'OTP has expired’';

    await this.userService.verifyOtpCode(user, code, errorMessage);

    return {
      success: true,
    };
  }

  async updatePassword(user: IDriver | IPassenger, password: string) {
    const userDoc = await this.userRepo.findById(user._id);

    const hashedPassword = await this.encryptHelper.hash(password);
    userDoc.password = hashedPassword;

    await this.userRepo.updateOne(
      {
        _id: user._id,
      },
      {
        password: hashedPassword,
        hasChangedPassword: true,
      },
    );
  }

  async getAllRoles() {
    return await this.roleRepo.find({});
  }

  async getAllUserRoles() {
    return await this.userRepo.find().populate('roles');
  }

  async sessionExists(params: LoginDto): Promise<{
    exists: boolean;
    user: IDriver | IPassenger;
  }> {
    const { email, password } = params;

    const user = await this.validateUser(email, password);

    const session = await this.userSessionService.checkSession(user._id);

    return {
      exists: !!session,
      user,
    };
  }
}
````

## File: src/modules/auth/auth.controller.ts
````typescript
import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
  Logger,
  UseInterceptors,
  UploadedFile,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import {
  EmailConfirmationDto,
  ForgotPasswordDto,
  LoginDto,
  // TCodeLoginDto,
} from './dto';
import { BaseRegistrationDto } from './dto/base-registeration.dto';
import { IDriver, IPassenger } from 'src/core/interfaces';
import { User as UserDecorator } from 'src/core/decorators';
import { AuthGuard } from 'src/core/guards';
import { SecretsService } from 'src/global/secrets/service';
import { PortalType } from 'src/core/enums/auth.enum';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiBody,
  ApiConsumes,
} from '@nestjs/swagger';
import { AuthUserResponseDto, BaseResponseDto } from './dto/auth-response.dto';
import { SendPhoneOtpDto, VerifyPhoneOtpDto } from './dto/send-phone-otp.dto';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  private logger = new Logger(AuthController.name);
  constructor(
    private authService: AuthService,
    private secretSecret: SecretsService,
  ) {}

  @Post('phone/send-otp')
  @ApiOperation({ summary: 'Send OTP to phone number' })
  @ApiResponse({
    status: 200,
    description: 'OTP sent successfully',
    type: BaseResponseDto<{ sent: boolean }>,
  })
  @ApiResponse({ status: 400, description: 'Bad request - Invalid input' })
  @ApiResponse({ status: 500, description: 'Internal server error' })
  @ApiBody({
    schema: {
      properties: {
        phoneNumber: {
          type: 'string',
          example: '+2348012345678',
          description: 'Phone number in E.164 format',
        },
      },
    },
  })
  @HttpCode(HttpStatus.OK)
  async sendPhoneOtp(@Body() body: SendPhoneOtpDto) {
    const data = await this.authService.sendPhoneVerificationOtp(body);
    return {
      data,
      message: 'OTP sent succesfully',
    };
  }

  @Post('phone/verify-otp')
  @ApiOperation({ summary: 'Verify OTP for phone number' })
  @ApiResponse({
    status: 200,
    description: 'OTP verified successfully',
    type: BaseResponseDto<{ verified: boolean }>,
  })
  @ApiResponse({ status: 400, description: 'Bad request - Invalid input' })
  @ApiResponse({ status: 500, description: 'Internal server error' })
  @ApiBody({
    schema: {
      properties: {
        phoneNumber: {
          type: 'string',
          example: '+2348012345678',
          description: 'Phone number in E.164 format',
        },
        otp: {
          type: 'string',
          example: '123456',
          description: '6-digit OTP code',
        },
      },
    },
  })
  @HttpCode(HttpStatus.OK)
  async verifyPhoneOtp(@Body() body: VerifyPhoneOtpDto) {
    const data = await this.authService.verifyPhoneNumberOtp(body);
    return {
      data,
      message: 'OTP verified successfully',
    };
  }

  @Post('/create-user')
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({
    status: 201,
    description: 'User successfully created',
    type: BaseResponseDto<AuthUserResponseDto>,
  })
  @ApiResponse({ status: 400, description: 'Bad request - Invalid input' })
  async register(
    @Body() body: BaseRegistrationDto,
    @Body('portalType') portalType: PortalType,
  ) {
    const data = await this.authService.createPortalUser(body, portalType);

    return {
      data,
      message: 'User created successfully',
    };
  }

  @Post('login')
  @ApiOperation({ summary: 'Login user' })
  @ApiResponse({
    status: 200,
    description: 'Login successful',
    type: BaseResponseDto<AuthUserResponseDto>,
  })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  async login(@Body() loginDto: LoginDto) {
    const data = await this.authService.login(loginDto);

    return {
      data,
      message: 'Login successful',
    };
  }

  @UseGuards(AuthGuard)
  @Post('resend-verification')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Resend verification email' })
  @ApiResponse({
    status: 200,
    description: 'Verification code sent successfully',
    type: BaseResponseDto<{ sent: boolean }>,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async resendVerificationEmail(@UserDecorator() user: IDriver | IPassenger) {
    const data = await this.authService.resendVerificationEmail(user._id);

    return {
      data,
      message: 'Verification Code Sent Successfully',
    };
  }

  @HttpCode(HttpStatus.OK)
  @Post('/forgot-password')
  @ApiOperation({ summary: 'Request password reset' })
  @ApiResponse({
    status: 200,
    description: 'Password reset email sent',
    type: BaseResponseDto<{ sent: boolean }>,
  })
  @ApiResponse({ status: 404, description: 'User not found' })
  async forgotPassword(
    @Body() body: ForgotPasswordDto,
    @Body('callbackURL') query: string,
  ): Promise<object> {
    const data = await this.authService.forgotPassword(body.email, query);

    return {
      data,
      message: 'Password reset link has been sent to your email',
    };
  }

  @HttpCode(HttpStatus.OK)
  @Post('/reset-password')
  @ApiOperation({ summary: 'Reset password using code' })
  @ApiResponse({
    status: 200,
    description: 'Password changed successfully',
    type: BaseResponseDto<{ updated: boolean }>,
  })
  @ApiResponse({ status: 400, description: 'Invalid or expired code' })
  @ApiBody({
    schema: {
      properties: {
        code: { type: 'string', example: '123456' },
        password: { type: 'string', example: 'newPassword123' },
      },
    },
  })
  async resetPassword(
    @Body('code') code: string,
    @Body('password') password: string,
  ): Promise<object> {
    const data = await this.authService.resetPassword(code, password);

    return {
      data,
      message: 'Password Changed Successfully',
    };
  }

  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('/confirmation')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Verify email address' })
  @ApiResponse({
    status: 200,
    description: 'Email verified successfully',
    type: BaseResponseDto<AuthUserResponseDto>,
  })
  @ApiResponse({ status: 400, description: 'Invalid verification code' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async verifyEmail(
    @UserDecorator() user: IDriver | IPassenger,
    @Body() body: EmailConfirmationDto,
  ): Promise<object> {
    const data = await this.authService.verifyUserEmail(user._id, body.code);

    return {
      data,
      message: 'Email verified successfully',
    };
  }

  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @Get('/logout')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Logout user' })
  @ApiResponse({
    status: 200,
    description: 'Logged out successfully',
    type: BaseResponseDto<{ loggedOut: boolean }>,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async logout(@UserDecorator() user: IDriver | IPassenger): Promise<object> {
    const data = await this.authService.logoutUser(user._id);

    return {
      data,
      message: 'Logout successfully',
    };
  }

  // @HttpCode(HttpStatus.OK)
  // @Post('/tcode-auth')
  // @ApiOperation({ summary: 'Authenticate using temporary code' })
  // @ApiResponse({ status: 200, description: 'Authentication successful' })
  // @ApiResponse({ status: 401, description: 'Invalid code' })
  // async tCodeAuth(@Body() body: TCodeLoginDto) {
  //   const data = await this.authService.tCodeLogin(body.tCode);

  //   return {
  //     data,
  //     message: 'Authenticated successfully',
  //   };
  // }

  // @HttpCode(HttpStatus.OK)
  // @Post('/tcode_auth')
  // async tCodeAuthU(@Body() body: TCodeLoginDto) {
  //   return this.tCodeAuth(body);
  // }

  @HttpCode(HttpStatus.OK)
  @UseGuards(AuthGuard)
  @Get('/all-users')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get all users' })
  @ApiResponse({
    status: 200,
    description: 'Users fetched successfully',
    type: BaseResponseDto<AuthUserResponseDto[]>,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getAllUsers() {
    const data = await this.authService.getAllUsers();

    return {
      data,
      message: 'Users Fetched Successfully',
    };
  }

  @HttpCode(HttpStatus.OK)
  @Get('/user')
  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get current user info' })
  @ApiResponse({
    status: 200,
    description: 'User info fetched successfully',
    type: BaseResponseDto<AuthUserResponseDto>,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getUser(@UserDecorator() user: IDriver | IPassenger): Promise<object> {
    const data = await this.authService.getUserInfo(user.email);

    return {
      data,
      message: 'User Info Fetched Successfully',
    };
  }

  @UseGuards(AuthGuard)
  @UseInterceptors(FileInterceptor('avatar'))
  @Post('/user/upload-avatar')
  @ApiBearerAuth()
  @ApiConsumes('multipart/form-data')
  @ApiOperation({ summary: 'Upload user avatar' })
  @ApiResponse({
    status: 200,
    description: 'Avatar uploaded successfully',
    type: BaseResponseDto<AuthUserResponseDto>,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        avatar: {
          type: 'string',
          format: 'binary',
        },
      },
    },
  })
  async uploadAvatar(
    @UserDecorator() user: IDriver | IPassenger,
    @UploadedFile() file: Express.Multer.File,
  ) {
    const data = await this.authService.uploadAvatar(user._id, file);

    return {
      data,
      message: 'Avatar uploaded successfully',
    };
  }

  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('/change-password-confirmation')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Request password change confirmation' })
  @ApiResponse({
    status: 200,
    description: 'Confirmation code sent successfully',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async changePasswordConfirmation(
    @UserDecorator() user: IDriver | IPassenger,
    @Body('oldPassword') body: string,
  ): Promise<object> {
    const data = await this.authService.changePasswordConfirmation(user, body);

    return {
      data,
      message: 'Change Password Confirmation Sent Successfully',
    };
  }

  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('/verify-password-confirmation')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Verify password change confirmation code' })
  @ApiResponse({ status: 200, description: 'Code verified successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async verifychangePasswordConfirmation(
    @UserDecorator() user: IDriver | IPassenger,
    @Body('code') code: string,
  ): Promise<object> {
    const data = await this.authService.verifychangePasswordConfirmation(
      user,
      code,
    );

    return {
      data,
      message: 'Change Password Confirmation Sent Successfully',
    };
  }

  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('/change-password')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Change user password' })
  @ApiResponse({ status: 200, description: 'Password changed successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async updatePassword(
    @UserDecorator() user: IDriver | IPassenger,
    @Body('password') password: string,
  ): Promise<object> {
    const data = await this.authService.updatePassword(user, password);

    return {
      data,
      message: 'Password Changed Successfully',
    };
  }

  @HttpCode(HttpStatus.OK)
  @Get('/roles')
  @ApiOperation({ summary: 'Get all roles' })
  @ApiResponse({ status: 200, description: 'Roles fetched successfully' })
  async getAllRoles(): Promise<object> {
    const data = await this.authService.getAllRoles();

    return {
      data,
      message: 'All Roles Successfully',
    };
  }

  @HttpCode(HttpStatus.OK)
  @Get('/users')
  @ApiOperation({ summary: 'Get all users with their roles' })
  @ApiResponse({
    status: 200,
    description: 'Users with roles fetched successfully',
  })
  async getAllUsersAndRoles(): Promise<object> {
    const data = await this.authService.getAllUserRoles();

    return {
      data,
      message: 'All Users Successfully',
    };
  }
}
````

## File: package.json
````json
{
  "name": "ride-by",
  "version": "0.0.1",
  "description": "",
  "author": "",
  "private": true,
  "license": "UNLICENSED",
  "scripts": {
    "build": "nest build",
    "format": "prettier --write \"src/**/*.ts\" \"test/**/*.ts\"",
    "start": "nest start",
    "start:dev": "nest start --watch",
    "start:debug": "nest start --debug --watch",
    "start:prod": "node dist/main",
    "lint": "eslint \"{src,apps,libs,test}/**/*.ts\" --fix",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:cov": "jest --coverage",
    "test:debug": "node --inspect-brk -r tsconfig-paths/register -r ts-node/register node_modules/.bin/jest --runInBand",
    "test:e2e": "jest --config ./test/jest-e2e.json"
  },
  "dependencies": {
    "@googlemaps/google-maps-services-js": "^3.4.1",
    "@nestjs-modules/ioredis": "^2.0.2",
    "@nestjs-modules/mailer": "^2.0.2",
    "@nestjs/axios": "^4.0.0",
    "@nestjs/bull": "^11.0.2",
    "@nestjs/common": "^11.0.0",
    "@nestjs/config": "^4.0.0",
    "@nestjs/core": "^11.0.0",
    "@nestjs/mongoose": "^11.0.0",
    "@nestjs/passport": "^11.0.5",
    "@nestjs/platform-express": "^11.0.0",
    "@nestjs/platform-socket.io": "^11.0.0",
    "@nestjs/swagger": "^11.1.0",
    "@nestjs/terminus": "^11.0.0",
    "@nestjs/websockets": "^11.0.16",
    "@socket.io/redis-adapter": "^8.2.0",
    "aws-sdk": "^2.1692.0",
    "axios": "^1.8.4",
    "bcryptjs": "^3.0.2",
    "bull": "^4.16.5",
    "class-transformer": "^0.5.1",
    "class-validator": "^0.14.1",
    "cookie-parser": "^1.4.7",
    "dotenv": "^16.4.7",
    "ejs": "^3.1.10",
    "eslint-plugin-security": "^3.0.1",
    "firebase-admin": "^13.2.0",
    "ioredis": "^5.4.2",
    "mongoose": "^8.9.5",
    "nest-aws-sdk": "^3.1.0",
    "nodemailer": "^6.10.0",
    "otp-generator": "^4.0.1",
    "passport-jwt": "^4.0.1",
    "redis": "^4.7.0",
    "reflect-metadata": "^0.2.0",
    "rxjs": "^7.8.1",
    "swagger-ui-express": "^5.0.1",
    "twilio": "^5.5.2",
    "uuid": "^11.1.0"
  },
  "devDependencies": {
    "@nestjs/cli": "^11.0.0",
    "@nestjs/schematics": "^11.0.0",
    "@nestjs/testing": "^11.0.0",
    "@types/bull": "^3.15.9",
    "@types/cookie-parser": "^1.4.8",
    "@types/express": "^5.0.0",
    "@types/google__maps": "^0.5.20",
    "@types/jest": "^29.5.2",
    "@types/multer": "^1.4.12",
    "@types/node": "^20.3.1",
    "@types/nodemailer": "^6.4.17",
    "@types/supertest": "^6.0.0",
    "@types/uuid": "^10.0.0",
    "@typescript-eslint/eslint-plugin": "^8.0.0",
    "@typescript-eslint/parser": "^8.0.0",
    "eslint": "^8.0.0",
    "eslint-config-prettier": "^9.0.0",
    "eslint-plugin-prettier": "^5.0.0",
    "jest": "^29.5.0",
    "prettier": "^3.0.0",
    "source-map-support": "^0.5.21",
    "supertest": "^7.0.0",
    "ts-jest": "^29.1.0",
    "ts-loader": "^9.4.3",
    "ts-node": "^10.9.1",
    "tsconfig-paths": "^4.2.0",
    "typescript": "^5.1.3"
  },
  "jest": {
    "moduleFileExtensions": [
      "js",
      "json",
      "ts"
    ],
    "rootDir": "src",
    "testRegex": ".*\\.spec\\.ts$",
    "transform": {
      "^.+\\.(t|j)s$": "ts-jest"
    },
    "collectCoverageFrom": [
      "**/*.(t|j)s"
    ],
    "coverageDirectory": "../coverage",
    "testEnvironment": "node"
  }
}
````
