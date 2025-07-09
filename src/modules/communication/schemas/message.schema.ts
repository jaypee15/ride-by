import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { User } from '../../user/schemas/user.schema';
import { Booking } from '../../booking/schemas/booking.schema'; // Optional link to booking

export type MessageDocument = Message & Document;

@Schema({ timestamps: true, collection: 'messages' })
export class Message {
  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  })
  sender: User;

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  })
  receiver: User;

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Booking',
    required: false,
    index: true,
  })
  booking?: Booking; // Optional: Link message to a specific booking context

  @Prop({ type: String, required: true, trim: true, maxlength: 1000 })
  content: string;

  @Prop({ type: Date }) // Timestamp when the receiver read the message
  readAt?: Date;

  // createdAt, updatedAt handled by timestamps: true
}

export const MessageSchema = SchemaFactory.createForClass(Message);

// Index for fetching chat history between two users
MessageSchema.index({ sender: 1, receiver: 1, createdAt: -1 });
// Index for fetching messages related to a booking
MessageSchema.index({ booking: 1, createdAt: -1 });
