import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { ActionEnum, Subject } from 'src/core/interfaces';

@Schema({
  timestamps: true,
})
export class Action {
  @Prop({ enum: ActionEnum, default: ActionEnum.Read })
  action: ActionEnum;

  @Prop({
    type: String,
  })
  subject: Subject;

  @Prop()
  description: string;
}

export const ActionSchema = SchemaFactory.createForClass(Action);
