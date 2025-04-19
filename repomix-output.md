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
    config/
      config.module.ts
    database/
      database.module.ts
    driver/
      dto/
        driver-regidtration.dto.ts
      schemas/
        vehicle.schema.ts
      riders.module.ts
    geolocation/
      geolocation.module.ts
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
    passenger/
      dto/
        passenger.dto.ts
    rides/
      rides.module.ts
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
    twilio/
      twiio.module.ts
      twilio.service.ts
    user/
      schemas/
        action.schema.ts
        role.schema.ts
        token.schema.ts
        user.schema.ts
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

## File: src/modules/driver/riders.module.ts
````typescript
import { Module } from '@nestjs/common';

@Module({})
export class RidersModule {}
````

## File: src/modules/geolocation/geolocation.module.ts
````typescript
import { Module } from '@nestjs/common';

@Module({})
export class GeolocationModule {}
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

## File: src/modules/rides/rides.module.ts
````typescript
import { Module } from '@nestjs/common';

@Module({})
export class RidesModule {}
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

  //   async sendSms(to: string, body: string): Promise<boolean> {
  //     const { phoneNumber } = this.secretsService.twilio;
  //     if (!this.twilioClient || !phoneNumber) {
  //       this.logger.error(
  //         'Twilio client not initialized or phone number missing. Cannot send SMS.',
  //       );
  //       // Depending on requirements, you might throw an error or just return false
  //       throw new Error('SMS service is not configured properly.');
  //       // return false;
  //     }

  //     try {
  //       const message = await this.twilioClient.messages.create({
  //         body,
  //         from: phoneNumber,
  //         to, // Ensure 'to' number is in E.164 format (e.g., +23480...)
  //       });
  //       this.logger.log(`SMS sent successfully to ${to}, SID: ${message.sid}`);
  //       return true;
  //     } catch (error) {
  //       this.logger.error(
  //         `Failed to send SMS to ${to}: ${error.message}`,
  //         error.stack,
  //       );
  //       // Rethrow or handle specific Twilio errors (e.g., invalid number format)
  //       throw new Error(`Failed to send verification code: ${error.message}`);
  //       // return false;
  //     }
  //   }

  // --- Optional: If using Twilio Verify Service ---

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

## File: src/modules/user/user.module.ts
````typescript
import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { MongooseModule } from '@nestjs/mongoose';
import { Token, TokenSchema } from './schemas/token.schema';
import { UserSchema, User } from './schemas/user.schema';
import { roleSchema, Role } from './schemas/role.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Token.name, schema: TokenSchema },
      { name: User.name, schema: UserSchema },
      { name: Role.name, schema: roleSchema },
    ]),
  ],
  providers: [UserService],
  exports: [UserService],
})
export class UserModule {}
````

## File: src/modules/user/user.service.ts
````typescript
import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { DateHelper, ErrorHelper } from 'src/core/helpers';
import { IPassenger, IDriver } from 'src/core/interfaces';
import { TokenHelper } from 'src/global/utils/token.utils';
import { UserSessionService } from 'src/global/user-session/service';
import { Token } from './schemas/token.schema';
import { User } from './schemas/user.schema';

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

## File: src/modules/app.module.ts
````typescript
import { Module } from '@nestjs/common';
import { AuthGuard } from 'src/core/guards';
import { WsGuard } from 'src/core/guards/ws.guard';
import { AppGateway } from './app.gateway';

@Module({
  providers: [AppGateway, WsGuard, AuthGuard],
  imports: [],
})
export class AppModule {}
````

## File: src/modules/main.module.ts
````typescript
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { DatabaseModule } from './database/database.module';
import { RidesModule } from './rides/rides.module';
import { GeolocationModule } from './geolocation/geolocation.module';
import { RidersModule } from './driver/riders.module';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { MongooseModule } from '@nestjs/mongoose';
import { SecretsModule } from '../global/secrets/module';
import { SecretsService } from '../global/secrets/service';
import { AppModule } from './app.module';
import { GlobalModule } from 'src/global/global.module';
@Module({
  imports: [
    GlobalModule,
    DatabaseModule,
    ConfigModule,
    AuthModule,
    UserModule,
    RidesModule,
    RidersModule,
    GeolocationModule,
    AppModule,
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

## File: src/modules/driver/dto/driver-regidtration.dto.ts
````typescript
import { BaseRegistrationDto } from 'src/modules/auth/dto/base-registeration.dto';

// For the initial user creation, driver-specific details like license and vehicle info
// are usually collected *after* the account is created during an onboarding/verification flow.
// Therefore, this DTO extends the base without additional required fields for registration itself.

export class DriverRegistrationDto extends BaseRegistrationDto {}
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
}

export const UserSchema = SchemaFactory.createForClass(User);
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
````

## File: src/core/interfaces/user/index.ts
````typescript
export * from './user.interface';
export * from './role.interface';
````

## File: src/core/interfaces/user/user.interface.ts
````typescript
/* eslint-disable @typescript-eslint/no-explicit-any */
import { UserGender } from 'src/core/enums/user.enum';
import { UserStatus } from 'src/core/enums/user.enum';

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

## File: src/global/secrets/service.ts
````typescript
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class SecretsService extends ConfigService {
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
}
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
    .setTitle('Ride-By API')
    .setDescription('The Ride-By API documentation')
    .setVersion('1.0')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  await app.listen(PORT);
}
bootstrap();
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
import { DriverRegistrationDto } from '../driver/dto/driver-regidtration.dto';
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
    "@nestjs-modules/ioredis": "^2.0.2",
    "@nestjs-modules/mailer": "^2.0.2",
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
    "bcryptjs": "^3.0.2",
    "bull": "^4.16.5",
    "class-transformer": "^0.5.1",
    "class-validator": "^0.14.1",
    "cookie-parser": "^1.4.7",
    "dotenv": "^16.4.7",
    "ejs": "^3.1.10",
    "eslint-plugin-security": "^3.0.1",
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
    "twilio": "^5.5.2"
  },
  "devDependencies": {
    "@nestjs/cli": "^11.0.0",
    "@nestjs/schematics": "^11.0.0",
    "@nestjs/testing": "^11.0.0",
    "@types/bull": "^3.15.9",
    "@types/cookie-parser": "^1.4.8",
    "@types/express": "^5.0.0",
    "@types/jest": "^29.5.2",
    "@types/multer": "^1.4.12",
    "@types/node": "^20.3.1",
    "@types/nodemailer": "^6.4.17",
    "@types/supertest": "^6.0.0",
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
