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
}
