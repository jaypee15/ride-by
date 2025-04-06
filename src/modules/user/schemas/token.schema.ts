import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MSchema } from 'mongoose';
import { User } from './user.schema';

@Schema({
  timestamps: true,
})
export class Token extends Document {
  @Prop({ type: MSchema.Types.ObjectId, ref: 'User' })
  user: User;

  @Prop({ required: true, type: String })
  code: string;

  @Prop({ type: Boolean, default: false })
  isUsed: boolean;

  @Prop({ required: false, type: Date })
  expirationTime: Date;
}

export const TokenSchema = SchemaFactory.createForClass(Token);
