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
