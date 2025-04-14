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
