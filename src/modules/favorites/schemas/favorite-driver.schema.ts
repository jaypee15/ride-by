import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { User } from '../../user/schemas/user.schema';

export type FavoriteDriverDocument = FavoriteDriver & Document;

@Schema({ timestamps: true, collection: 'favorite_drivers' })
export class FavoriteDriver {
  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true })
  passenger: User;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true })
  driver: User;
}

export const FavoriteDriverSchema = SchemaFactory.createForClass(FavoriteDriver);
FavoriteDriverSchema.index({ passenger: 1, driver: 1 }, { unique: true });
