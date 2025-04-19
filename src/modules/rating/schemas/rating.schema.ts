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
