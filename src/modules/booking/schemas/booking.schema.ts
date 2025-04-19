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
