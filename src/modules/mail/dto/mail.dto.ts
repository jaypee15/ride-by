import {
  IsArray,
  IsBoolean,
  IsEnum,
  IsNumber,
  IsObject,
  IsOptional,
  IsString,
} from 'class-validator';
import { MailType } from '../enums/mail.enum';
import { envType } from 'src/core/interfaces';
import { PaginationDto } from 'src/core/dto';

export class SendMailDto {
  @IsArray()
  @IsOptional()
  to?: string[];

  @IsString()
  @IsOptional()
  body?: string;

  @IsString()
  @IsOptional()
  cc?: string;

  @IsString()
  subject: string;

  @IsEnum(MailType)
  type: MailType;

  @IsObject()
  data: object & { env?: envType };

  @IsBoolean()
  saveAsNotification: boolean;
}

export class GetScheduleEmailsDto extends PaginationDto {
  @IsNumber()
  @IsOptional()
  limit: number;

  @IsNumber()
  @IsOptional()
  page: number;
}
