import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({
  timestamps: true,
})
export class Country extends Document {
  @Prop({
    type: String,
    required: true,
  })
  name: string;

  @Prop({
    type: String,
    required: true,
  })
  alpha2code: string;

  @Prop({
    type: String,
    required: true,
  })
  alpha3code: string;

  @Prop({
    type: String,
    required: true,
  })
  callingCode: string;

  @Prop({
    type: String,
    required: true,
  })
  continent: string;

  @Prop({
    type: [String],
    required: false,
    default: [],
  })
  currencies: string[];
}

export const CountrySchema = SchemaFactory.createForClass(Country);
