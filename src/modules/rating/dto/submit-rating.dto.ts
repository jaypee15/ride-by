import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsInt,
  IsMongoId,
  IsNotEmpty,
  IsOptional,
  IsString,
  Max,
  MaxLength,
  Min,
} from 'class-validator';

export class SubmitRatingDto {
  @ApiProperty({
    description: 'ID of the completed booking being rated',
    example: '605c72ef4e79a3a3e8f2d3b4',
  })
  @IsMongoId()
  @IsNotEmpty()
  bookingId: string;

  @ApiProperty({ description: 'Rating score (1 to 5)', example: 5 })
  @IsInt()
  @Min(1)
  @Max(5)
  @IsNotEmpty()
  score: number;

  @ApiPropertyOptional({
    description: 'Optional comment for the rating',
    maxLength: 500,
    example: 'Great ride!',
  })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  comment?: string;
}
