import { Schema, SchemaFactory, Prop } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({
  timestamps: true,
})
export class Email extends Document {
  @Prop({ type: String })
  event: string;

  @Prop({ type: String })
  event_id: string;

  @Prop({ type: String })
  email: string;

  @Prop({ type: String, required: false })
  ip: string;

  @Prop({ type: String, required: false })
  user_agent: string;

  @Prop({ type: String, required: false })
  url: string;

  @Prop({ type: String, required: false })
  response: string;

  @Prop({ type: String, required: false })
  response_code: string;

  @Prop({ type: String, required: false })
  bounce_category: string;

  @Prop({ type: String, required: false })
  reason: string;

  @Prop({ type: String })
  timestamp: string;

  @Prop({ type: String })
  sending_stream: string;

  @Prop({ type: String })
  category: string;

  @Prop({ type: { variable_a: String, variable_b: String }, required: false })
  custom_variables?: { variable_a: String; variable_b: String };

  @Prop({ type: String })
  message_id: string;
}

export const EmailSchema = SchemaFactory.createForClass(Email);
