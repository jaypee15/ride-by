import { ApiProperty } from '@nestjs/swagger';
import {
  IsMongoId,
  IsNotEmpty,
  IsOptional,
  IsString,
  MaxLength,
} from 'class-validator';

export class SendMessageDto {
  @ApiProperty({
    description: 'ID of the recipient user',
    example: '605c72ef4e79a3a3e8f2d3b4',
  })
  @IsMongoId()
  @IsNotEmpty()
  receiverId: string;

  @ApiProperty({
    description: 'The text content of the message',
    maxLength: 1000,
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(1000)
  content: string;

  @ApiProperty({
    description: 'Optional ID of the booking this message relates to',
    example: '605c72ef4e79a3a3e8f2d3b5',
    required: false,
  })
  @IsOptional()
  @IsMongoId()
  bookingId?: string;
}
