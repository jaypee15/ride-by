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
    filters/
      http-exception.filter.ts
      index.ts
    guards/
      authenticate.guard.ts
      index.ts
    helpers/
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
        auth.dto.ts
        index.ts
        update-user.dto.ts
      auth.controller.ts
      auth.module.ts
      auth.service.ts
    config/
      config.module.ts
    database/
      database.module.ts
    driver/
      riders.module.ts
    geolocation/
      geolocation.module.ts
    health/
      health.controller.ts
      health.module.ts
    mail/
      enums/
        index.ts
        mail.enum.ts
      schema/
        email.schema.ts
      templates/
        email/
          emailnotification.ejs
        confrimation.ejs
      mail.controller.ts
      mail.event.ts
      mail.module.ts
      mail.service.ts
    rides/
      rides.module.ts
    users/
      users.module.ts
  app.module.ts
  main.ts
test/
  app.e2e-spec.ts
  jest-e2e.json
.eslintrc.js
.gitignore
.prettierrc
nest-cli.json
package.json
README.md
tsconfig.build.json
tsconfig.json
```

# Files

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

## File: src/modules/driver/riders.module.ts
````typescript
import { Module } from '@nestjs/common';

@Module({})
export class RidersModule {}
````

## File: src/core/adpater/index.ts
````typescript
export * from './redis.adpater';
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
    super(app);
    const configService = app.get(SecretsService);

    const pubClient = createClient({
      socket: {
        host: configService.userSessionRedis.REDIS_HOST,
        port: configService.userSessionRedis.REDIS_PORT,
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
}
````

## File: src/core/constants/base.constant.ts
````typescript
export const PASSWORD_PATTERN = '^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.{8,})';
export const BASE_COMMISSION = 0.3;
export const DRIVER_ONBOARDING_STEPS = 8;
export const PASSENGER_ONBOARDING_STEPS = 5;
````

## File: src/core/constants/index.ts
````typescript
export * from './base.constant';
export * from './messages.constant';
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

## File: src/core/enums/auth.enum.ts
````typescript
export enum PortalType {
  DRIVER = 'DRIVER',
  PASSENGER = 'PASSENGER',
  ADMIN = 'ADMIN',
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

## File: src/core/guards/index.ts
````typescript
export * from './authenticate.guard';
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

## File: src/core/helpers/index.ts
````typescript
export * from './error.utils';
export * from './ecrypt.helper';
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

## File: src/core/interfaces/http/index.ts
````typescript
export * from './http.interface';
````

## File: src/core/interfaces/user/index.ts
````typescript
export * from './user.interface';
export * from './role.interface';

export enum StatusEnum {
  ACTIVE = 'Active',
  INACTIVE = 'inActive',
}
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

export enum UserGender {
  MALE = 'MALE',
  FEMALE = 'FEMALE',
  OTHERS = 'OTHERS',
}
````

## File: src/core/interfaces/user/user.interface.ts
````typescript
/* eslint-disable @typescript-eslint/no-explicit-any */
import { StatusEnum } from '.';
import { UserGender } from './role.interface';

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
  status?: StatusEnum;
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
  status?: StatusEnum;
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
  status?: StatusEnum;
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
  status?: StatusEnum;
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
  status?: StatusEnum;
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

## File: src/global/secrets/module.ts
````typescript
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { SecretsService } from './service';

@Module({
  imports: [
    ConfigModule.forRoot({
      envFilePath: ['.env'],
    }),
  ],
  providers: [SecretsService],
  exports: [SecretsService],
})
export class SecretsModule {}
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
}
````

## File: src/global/user-session/module.ts
````typescript
import { Module } from '@nestjs/common';
import { RedisModule, RedisModuleOptions } from '@nestjs-modules/ioredis';

import { SecretsService } from '../secrets/service';
import { UserSessionService } from './service';

@Module({
  imports: [
    RedisModule.forRootAsync({
      useFactory: ({ userSessionRedis }: SecretsService) => {
        return {
          config: {
            host: userSessionRedis.REDIS_HOST,
            port: userSessionRedis.REDIS_PORT,
            username: userSessionRedis.REDIS_USER,
            password: userSessionRedis.REDIS_PASSWORD,
          },
        } as unknown as RedisModuleOptions;
      },
      inject: [SecretsService],
    }),
  ],
  providers: [UserSessionService],
  exports: [UserSessionService],
})
export class UserSessionModule {}
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

## File: src/modules/auth/dto/auth.dto.ts
````typescript
import {
  IsBoolean,
  IsEmail,
  IsEnum,
  IsObject,
  IsOptional,
  IsString,
  IsUrl,
} from 'class-validator';
import { PASSWORD_PATTERN } from 'src/core/constants';
import { PortalType } from 'src/core/enums/auth.enum';
import { IsMatchPattern } from 'src/core/validators';

export class EmailConfirmationDto {
  @IsString()
  code: string;
}

export class TCodeLoginDto {
  @IsString()
  tCode: string;

  @IsString()
  portalType: PortalType;
}

export class CallbackURLDto {
  @IsUrl({ require_tld: false })
  @IsOptional()
  callbackURL: string;
}

export class RefreshTokenDto {
  @IsString()
  token: string;
}

export class ForgotPasswordDto {
  @IsString()
  @IsEmail()
  email: string;
}

export class AuthDto {
  @IsString()
  @IsOptional()
  firstName: string;

  @IsString()
  @IsOptional()
  lastName: string;

  @IsString()
  @IsEmail()
  email: string;

  @IsString()
  @IsMatchPattern(PASSWORD_PATTERN)
  password: string;
}

export class XternCareerPath {
  @IsString()
  email: string;

  @IsOptional()
  @IsString()
  reasonToJoin?: string;

  @IsString()
  @IsOptional()
  profession?: string;

  @IsString()
  @IsOptional()
  pathway?: string;

  @IsObject()
  @IsOptional()
  techStacks?: object;

  @IsString()
  @IsOptional()
  assessmentScore?: string;
}

export class LoginDto {
  @IsString()
  @IsEmail()
  email: string;

  @IsString()
  password: string;

  @IsEnum(PortalType)
  portalType: PortalType;

  @IsOptional()
  @IsBoolean()
  rememberMe = false;
}
````

## File: src/modules/auth/dto/index.ts
````typescript
export * from './auth.dto';
export * from './update-user.dto';
````

## File: src/modules/auth/dto/update-user.dto.ts
````typescript
import { IsOptional, IsString, IsObject, IsEnum } from 'class-validator';

export class UpdateUserDto {
  @IsOptional()
  @IsString()
  firstName?: string;

  @IsOptional()
  @IsString()
  lastName?: string;

  @IsOptional()
  @IsString()
  about?: string;

  @IsOptional()
  @IsString()
  email?: string;
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
  AuthDto,
  EmailConfirmationDto,
  ForgotPasswordDto,
  LoginDto,
  TCodeLoginDto,
} from './dto';

import { IDriver, IPassenger } from 'src/core/interfaces';
import { User as UserDecorator } from 'src/core/decorators';
import { AuthGuard } from 'src/core/guards';
import { SecretsService } from 'src/global/secrets/service';
import { PortalType } from 'src/core/enums/auth.enum';
import { FileInterceptor } from '@nestjs/platform-express';

@Controller('auth')
export class AuthController {
  private logger = new Logger(AuthController.name);
  constructor(
    private authService: AuthService,
    private secretSecret: SecretsService,
  ) {}

  @Post('/create-user')
  async register(
    @Body() body: AuthDto,
    @Body('portalType') portalType: PortalType,
  ) {
    const data = await this.authService.createPortalUser(body, portalType);

    return {
      data,
      message: 'User created successfully',
    };
  }

  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    const data = await this.authService.login(loginDto);

    return {
      data,
      message: 'Login successful',
    };
  }

  @UseGuards(AuthGuard)
  @Post('resend-verification')
  async resendVerificationEmail(@UserDecorator() user: IDriver | IPassenger) {
    const data = await this.authService.resendVerificationEmail(user._id);

    return {
      data,
      message: 'Verification Code Sent Successfully',
    };
  }

  @HttpCode(HttpStatus.OK)
  @Post('/forgot-password')
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
  async logout(@UserDecorator() user: IDriver | IPassenger): Promise<object> {
    const data = await this.authService.logoutUser(user._id);

    return {
      data,
      message: 'Logout successfully',
    };
  }

  // delicate
  @HttpCode(HttpStatus.OK)
  @Get('/sync-users')
  async syncUsers() {
    const data = await this.authService.syncUsers();

    return {
      data,
      message: 'Users Synced successfully',
    };
  }

  @HttpCode(HttpStatus.OK)
  @Post('/tcode-auth')
  async tCodeAuth(@Body() body: TCodeLoginDto) {
    const data = await this.authService.tCodeLogin(body.tCode);

    return {
      data,
      message: 'Authenticated successfully',
    };
  }

  @HttpCode(HttpStatus.OK)
  @Post('/tcode_auth')
  async tCodeAuthU(@Body() body: TCodeLoginDto) {
    return this.tCodeAuth(body);
  }

  @HttpCode(HttpStatus.OK)
  @UseGuards(AuthGuard)
  @Get('/all-users')
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
  async getAllRoles(): Promise<object> {
    const data = await this.authService.getAllRoles();

    return {
      data,
      message: 'All Roles Successfully',
    };
  }

  @HttpCode(HttpStatus.OK)
  @Get('/users')
  async getAllUsersAndRoles(): Promise<object> {
    const data = await this.authService.getAllUserRoles();

    return {
      data,
      message: 'All Users Successfully',
    };
  }
}
````

## File: src/modules/auth/auth.module.ts
````typescript
import { Module } from '@nestjs/common';

@Module({})
export class AuthModule {}
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
import {
  UserLoginStrategy,
  IDriver,
  IPassenger,
  StatusEnum,
  RoleNameEnum,
} from 'src/core/interfaces';
import { DriverRegistrationDto } from '../driver/dto/driver.dto';
import { PassengerRegistrationDto } from '../passenger/dto/passenger.dto';
import { UserService } from '../user/user.service';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Token } from '../user/schemas/token.entity';
import { MailEvent } from '../mail/mail.event';
import { UserSessionService } from 'src/global/user-session/service';
import { TokenHelper } from 'src/global/utils/token.utils';
import { LoginDto } from './dto/auth.dto.ts';
import { Country } from '../seed/schemas';
import { PortalType } from 'src/core/enums/auth.enum';
import { Role } from '../admin/entities/role.entity';
import { UpdateUserDto } from './dto/update-user.dto';
import { AwsS3Service } from '../aws-s3-bucket';
import { User } from './entities/schemas';
import { UserInfoResponse } from 'src/core/interfaces/auth/auth.interfaces';

@Injectable()
export class AuthService {
  private logger = new Logger(AuthService.name);

  constructor(
    @InjectModel(Token.name) private tokenRepo: Model<Token>,
    @InjectModel(Role.name) private roleRepo: Model<Role>,
    @InjectModel(User.name) private userRepo: Model<User>,
    @InjectModel(Country.name)
    private userService: UserService,
    private mailEvent: MailEvent,
    private encryptHelper: EncryptHelper,
    private tokenHelper: TokenHelper,
    private userSessionService: UserSessionService,
    private awsS3Service: AwsS3Service,
  ) {}

  async createPortalUser(
    payload: MentorRegistrationDto | XternRegistrationDto,
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
    payload: MentorRegistrationDto | XternRegistrationDto,
    options: {
      strategy: UserLoginStrategy;
      portalType: PortalType;
      adminCreated?: boolean;
    },
    roleNames?: RoleNameEnum[],
  ): Promise<IPassenger | IDriver> {
    const { email } = payload;
    const { strategy, portalType, adminCreated } = options;

    const emailQuery = {
      email: email.toLowerCase(),
    };

    let emailExist, user;

    if (!portalType) {
      ErrorHelper.BadRequestException(PORTAL_TYPE_ERROR);
    }

    emailExist = await this.userRepo.findOne(emailQuery, { getDeleted: true });

    if (emailExist) {
      ErrorHelper.BadRequestException(EMAIL_ALREADY_EXISTS);
    }

    const roleData = await this.roleRepo.findOne({ name: portalType });

    user = await this.userRepo.create({
      email: payload.email.toLowerCase(),
      password: await this.encryptHelper.hash(payload.password),
      firstName: payload.firstName,
      lastName: payload.lastName,
      country: payload.country,
      strategy,
      hasChangedPassword: strategy === UserLoginStrategy.LOCAL,
      emailConfirm: strategy === UserLoginStrategy.LOCAL ? false : true,
      portalType: portalType,
      roles: [roleData],
    });

    return user.toObject();
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

    if (user.status === StatusEnum.INACTIVE) {
      ErrorHelper.BadRequestException('Your account is inactive');
    }

    const roleNames = user.roles.map((role) => role.name);

    if (!roleNames.includes(portalType as any)) {
      ErrorHelper.ForbiddenException(
        'Forbidden: You does not have the required role to access this route.',
      );
    }

    return user.toObject();
  }

  async resendVerificationEmail(userId: string) {
    const user = await this.userRepo.findById(userId);

    if (!user) {
      ErrorHelper.BadRequestException('User not found');
    }

    if (user.emailConfirm) {
      ErrorHelper.BadRequestException('Email already confirmed');
    }

    const confirmationCode = await this.userService.generateOtpCode(
      user.toObject(),
    );

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
      user.toObject(),
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

    await this.userService.verifyOtpCode(user.toObject(), code);

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

    await this.userService.verifyOtpCode(user.toObject(), code, errorMessage);

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

  async syncUsers() {
    return await this.userService.syncUsers();
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

  async getUserInfo(email: string): Promise<UserInfoResponse> {
    const user = await this.userRepo.findOne({ email });

    if (!user) {
      ErrorHelper.NotFoundException('No User Found.');
    }

    return { ...user.toJSON() };
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

    return updatedUser.toObject();
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

## File: src/modules/mail/templates/email/emailnotification.ejs
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

## File: src/modules/mail/templates/confrimation.ejs
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

## File: src/modules/mail/mail.controller.ts
````typescript
import { Body, Controller, Logger, Post } from '@nestjs/common';
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
import { Token, TokenSchema } from '../user/schemas/token.entity';
import { UserSchema, User } from '../auth/entities/schemas';
import { Role, roleSchema } from '../admin/entities/role.entity';
import { Rider, RiderSchema } from '../rider/entities/rider.entity';
import { Rides, Rideschema } from '../rider/entities/rides.entity';
import { EmailProcessor } from './cron-job/email.processor';

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
      { name: Rider.name, schema: RiderSchema },
      { name: Rides.name, schema: Rideschema },
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

## File: src/modules/rides/rides.module.ts
````typescript
import { Module } from '@nestjs/common';

@Module({})
export class RidesModule {}
````

## File: src/modules/users/users.module.ts
````typescript
import { Module } from '@nestjs/common';

@Module({})
export class UsersModule {}
````

## File: src/app.module.ts
````typescript
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { DatabaseModule } from './modules/database/database.module';
import { RidesModule } from './modules/rides/rides.module';
import { GeolocationModule } from './modules/geolocation/geolocation.module';
import { RidersModule } from './modules/driver/riders.module';
import { AuthModule } from './modules/auth/auth.module';
import { UsersModule } from './modules/users/users.module';
import { MongooseModule } from '@nestjs/mongoose';
import { SecretsModule } from './global/secrets/module';
import { SecretsService } from './global/secrets/service';
@Module({
  imports: [
    DatabaseModule,
    ConfigModule,
    AuthModule,
    UsersModule,
    RidesModule,
    RidersModule,
    GeolocationModule,
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
export class AppModule {}
````

## File: test/app.e2e-spec.ts
````typescript
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from './../src/app.module';

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

## File: nest-cli.json
````json
{
  "$schema": "https://json.schemastore.org/nest-cli",
  "collection": "@nestjs/schematics",
  "sourceRoot": "src",
  "compilerOptions": {
    "deleteOutDir": true
  }
}
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

## File: src/core/dto/index.ts
````typescript
export * from './page-meta.dto';
export * from './page-options.dto';
export * from './pagination.dto';
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

## File: src/core/interfaces/index.ts
````typescript
export * from './http';
export * from './user';
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

## File: src/main.ts
````typescript
import { NestFactory } from '@nestjs/core';
import * as express from 'express';
import { AppModule } from './app.module';
import { SecretsService } from './global/secrets/service';
import * as cookieParser from 'cookie-parser';
import { ValidationPipe } from '@nestjs/common';
import { HttpExceptionFilter } from './core/filters';
import { LoggerInterceptor, TransformInterceptor } from './core/interceptors';
import { MongooseModule } from '@nestjs/mongoose';
import { RedisIoAdapter } from './core/adpater';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
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
    "@socket.io/redis-adapter": "^8.2.0",
    "bcryptjs": "^3.0.2",
    "bull": "^4.16.5",
    "class-transformer": "^0.5.1",
    "class-validator": "^0.14.1",
    "cookie-parser": "^1.4.7",
    "dotenv": "^16.4.7",
    "ejs": "^3.1.10",
    "ioredis": "^5.4.2",
    "mongoose": "^8.9.5",
    "nodemailer": "^6.10.0",
    "otp-generator": "^4.0.1",
    "passport-jwt": "^4.0.1",
    "redis": "^4.7.0",
    "reflect-metadata": "^0.2.0",
    "rxjs": "^7.8.1",
    "swagger-ui-express": "^5.0.1"
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
