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
