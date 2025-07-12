import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { RoleNameEnum } from 'src/core/interfaces';
import { Action, ActionSchema } from './action.schema';

export type RoleDocument = Role & Document;

@Schema({
  timestamps: true,
})
export class Role extends Document {
  @Prop({
    type: String,
    nullable: false,
    unique: true,
  })
  name: RoleNameEnum;

  @Prop({
    type: String,
    nullable: true,
  })
  description: string;

  @Prop({
    type: [ActionSchema],
  })
  actions: Action[];
}

export const roleSchema = SchemaFactory.createForClass(Role);
