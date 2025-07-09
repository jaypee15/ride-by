import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsInt,
  IsMongoId,
  IsNotEmpty,
  IsOptional,
  IsString,
  Min,
} from 'class-validator';

export class CreateBookingDto {
  @ApiProperty({
    description: 'ID of the ride to book',
    example: '605c72ef4e79a3a3e8f2d3b4',
  })
  @IsMongoId()
  @IsNotEmpty()
  rideId: string;

  @ApiProperty({ description: 'Number of seats to book', example: 1 })
  @IsInt()
  @Min(1)
  @IsNotEmpty()
  seatsNeeded: number;

  @ApiPropertyOptional({
    description: 'Proposed or agreed pickup address/description',
    example: 'Meet at Mobil Gas Station, Ikeja',
  })
  @IsOptional()
  @IsString()
  pickupAddress?: string;

  @ApiPropertyOptional({
    description: 'Proposed or agreed dropoff address/description',
    example: 'UI Main Gate',
  })
  @IsOptional()
  @IsString()
  dropoffAddress?: string;
}
