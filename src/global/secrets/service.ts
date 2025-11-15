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

  get resend() {
    return {
      RESEND_API_KEY: this.get<string>('RESEND_API_KEY', ''),
      RESEND_FROM_EMAIL: this.get<string>('RESEND_FROM_EMAIL', ''),
      RESEND_FROM_NAME: this.get<string>('RESEND_FROM_NAME', 'TravEazi Team'),
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

  get passwordReset() {
    return {
      PASSWORD_RESET_CALLBACK_URL: this.get<string>(
        'PASSWORD_RESET_CALLBACK_URL',
        '',
      ),
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
