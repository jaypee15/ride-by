import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { User } from '../../user/schemas/user.schema'; // Adjust path
import { Vehicle } from '../../driver/schemas/vehicle.schema'; // Adjust path
import { RideStatus } from '../enums/ride-status.enum';

// Simple Point Schema for GeoJSON
@Schema({ _id: false }) // No separate ID for point subdocuments
class Point {
  @Prop({ type: String, enum: ['Point'], required: true, default: 'Point' })
  type: string;

  @Prop({ type: [Number], required: true }) // [longitude, latitude]
  coordinates: number[];
}
const PointSchema = SchemaFactory.createForClass(Point);

export type RideDocument = Ride & Document;

@Schema({ timestamps: true, collection: 'rides' })
export class Ride {
  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  })
  driver: User;

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Vehicle',
    required: true,
    index: true,
  })
  vehicle: Vehicle;

  @Prop({ type: PointSchema, required: true })
  origin: Point;

  @Prop({ type: PointSchema, required: true })
  destination: Point;

  @Prop({ type: [PointSchema], default: [] }) // Array of waypoints
  waypoints?: Point[];

  @Prop({ type: String, required: true })
  originAddress: string; // User-friendly origin address

  @Prop({ type: String, required: true })
  destinationAddress: string; // User-friendly destination address

  @Prop({ type: Date, required: true, index: true })
  departureTime: Date;

  @Prop({ type: Date }) // Can be calculated/updated
  estimatedArrivalTime?: Date;

  @Prop({ type: Number, required: true, min: 0 })
  initialSeats: number; // Seats the vehicle had when ride was created

  @Prop({ type: Number, required: true, min: 0 })
  availableSeats: number; // Current available seats (decreases with bookings)

  @Prop({ type: Number, required: true, min: 0 })
  pricePerSeat: number;

  @Prop({
    type: String,
    enum: RideStatus,
    default: RideStatus.SCHEDULED,
    index: true,
  })
  status: RideStatus;

  @Prop({ type: [String], default: [] })
  preferences?: string[]; // e.g., "No Smoking", "Pets Allowed"

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'Booking', default: [] })
  bookings: mongoose.Schema.Types.ObjectId[]; // Refs to Booking documents for this ride

  @Prop({ type: PointSchema, required: false, index: '2dsphere' }) // Add geospatial index if querying by location
  currentLocation?: Point;

  @Prop({ type: Date })
  lastLocationUpdate?: Date;
}

export const RideSchema = SchemaFactory.createForClass(Ride);

// Geospatial index for efficient location-based searching
RideSchema.index({ origin: '2dsphere', destination: '2dsphere' });
