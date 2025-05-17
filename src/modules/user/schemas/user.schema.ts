import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { Role } from './role.schema';
import {
  UserGender,
  UserStatus,
  DriverVerificationStatus,
} from 'src/core/enums/user.enum';
import { UserLoginStrategy } from 'src/core/interfaces';
import { Vehicle } from '../../driver/schemas/vehicle.schema';

export type UserDocument = User & Document;

@Schema({ timestamps: true })
export class User {
  @Prop({ type: String, required: false, trim: true })
  firstName: string;

  @Prop({ type: String, required: false, trim: true })
  lastName: string;

  @Prop({
    type: String,
    unique: true,
    lowercase: true,
    trim: true,
    index: true,
    sparse: true,
  })
  email?: string;

  @Prop({ type: String, required: false, select: false }) // Required only for LOCAL strategy initially
  password?: string;

  @Prop({
    type: String,
    unique: true,
    sparse: true,
    index: true,
    required: true,
  }) // Unique phone number, sparse allows multiple nulls
  phoneNumber?: string;

  @Prop({ type: Boolean, default: false })
  phoneVerified: boolean;

  @Prop({ type: Boolean, default: false })
  emailConfirm: boolean;

  @Prop({ type: String, enum: UserGender })
  gender?: UserGender;

  @Prop({ type: String })
  avatar?: string;

  @Prop({ type: String })
  about?: string;

  @Prop({ type: String })
  country?: string;

  @Prop({
    type: String,
    enum: UserStatus,
    default: UserStatus.PENDING_EMAIL_VERIFICATION,
  })
  status: UserStatus;

  @Prop({
    type: String,
    enum: UserLoginStrategy,
    default: UserLoginStrategy.LOCAL,
  })
  strategy: UserLoginStrategy;

  @Prop({
    type: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Role' }],
    required: true,
  })
  roles: Role[];

  @Prop({ type: Date })
  lastSeen?: Date;

  // --- Driver Specific Fields (Optional) ---

  @Prop({
    type: String,
    enum: DriverVerificationStatus,
    default: DriverVerificationStatus.NOT_SUBMITTED,
  })
  driverVerificationStatus?: DriverVerificationStatus;

  @Prop({ type: String })
  driverLicenseNumber?: string;

  @Prop({ type: Date })
  driverLicenseExpiry?: Date;

  @Prop({ type: String })
  driverLicenseFrontImageUrl?: string;

  @Prop({ type: String })
  driverLicenseBackImageUrl?: string;

  @Prop({ type: String })
  driverRejectionReason?: string;

  @Prop({ type: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Vehicle' }] })
  vehicles?: Vehicle[];

  // --- Safety & Rating Fields ---

  @Prop({
    type: [
      {
        name: { type: String, required: true },
        phone: { type: String, required: true }, // Add validation for phone format if needed
      },
    ],
    default: [],
    _id: false, // Don't create separate _id for each contact
  })
  emergencyContacts: { name: string; phone: string }[];

  @Prop({ type: Number, default: 0, min: 0, max: 5 })
  averageRatingAsDriver: number;

  @Prop({ type: Number, default: 0, min: 0 })
  totalRatingsAsDriver: number; // Total number of ratings received as driver

  @Prop({ type: Number, default: 0, min: 0, max: 5 })
  averageRatingAsPassenger: number; // Calculated average rating when acting as passenger

  @Prop({ type: Number, default: 0, min: 0 })
  totalRatingsAsPassenger: number; // Total number of ratings received as passenger

  @Prop({ type: [String], default: [], index: true }) // Array to store FCM registration tokens
  deviceTokens: string[];
}

export const UserSchema = SchemaFactory.createForClass(User);
