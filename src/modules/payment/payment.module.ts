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
