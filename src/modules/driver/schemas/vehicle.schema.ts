import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { User } from '../../user/schemas/user.schema'; // Adjust path
import { VehicleVerificationStatus } from 'src/core/enums/vehicle.enum';

export type VehicleDocument = Vehicle & Document;

@Schema({ timestamps: true })
export class Vehicle {
  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  })
  driver: User;

  @Prop({ type: String, required: true, trim: true })
  make: string; // e.g., Toyota

  @Prop({ type: String, required: true, trim: true })
  model: string; // e.g., Camry

  @Prop({ type: Number, required: true })
  year: number;

  @Prop({ type: String, required: true, trim: true })
  color: string;

  @Prop({
    type: String,
    required: true,
    unique: true,
    uppercase: true,
    trim: true,
    index: true,
  })
  plateNumber: string;

  @Prop({
    type: Number,
    required: true,
    min: 1,
    comment: 'Number of seats available for passengers (excluding driver)',
  })
  seatsAvailable: number;

  @Prop({ type: String })
  vehicleRegistrationImageUrl?: string;

  @Prop({ type: String })
  proofOfOwnershipImageUrl?: string; // e.g., Vehicle license

  @Prop({ type: String })
  vehicleInsuranceImageUrl?: string;

  @Prop({ type: Date })
  insuranceExpiryDate?: Date;

  @Prop({
    type: String,
    enum: VehicleVerificationStatus,
    default: VehicleVerificationStatus.NOT_SUBMITTED,
  })
  vehicleVerificationStatus: VehicleVerificationStatus;

  @Prop({ type: String })
  vehicleRejectionReason?: string;

  @Prop({ type: Boolean, default: false })
  isDefault: boolean; // If the driver has multiple vehicles, which one is primary

  @Prop({ type: [String], default: [] }) // Array of strings like "Air Conditioning", "USB Charging"
  features?: string[];
}

export const VehicleSchema = SchemaFactory.createForClass(Vehicle);
