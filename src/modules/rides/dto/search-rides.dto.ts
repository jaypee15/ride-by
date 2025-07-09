import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsDateString,
  IsInt,
  IsNotEmpty,
  IsOptional,
  Min,
  ValidateNested,
} from 'class-validator';
import { PaginationDto } from '../../../core/dto/page-options.dto'; // Adjust path
import { CoordinatesDto } from './coordinates.dto';

export class SearchRidesDto extends PaginationDto {
  // Inherit pagination fields
  @ApiProperty({
    description: 'Origin coordinates for search',
    type: CoordinatesDto,
  })
  @ValidateNested()
  @Type(() => CoordinatesDto)
  @IsNotEmpty()
  origin: CoordinatesDto;

  @ApiProperty({
    description: 'Destination coordinates for search',
    type: CoordinatesDto,
  })
  @ValidateNested()
  @Type(() => CoordinatesDto)
  @IsNotEmpty()
  destination: CoordinatesDto;

  @ApiProperty({
    description: 'Desired departure date (YYYY-MM-DD format)',
    example: '2025-08-15',
  })
  @IsDateString()
  @IsNotEmpty()
  departureDate: string; // We'll handle time range in the service

  @ApiProperty({ description: 'Number of seats required', example: 1 })
  @Type(() => Number) // Ensure transformation from query param string
  @IsInt()
  @Min(1)
  @IsNotEmpty()
  seatsNeeded: number;

  @ApiPropertyOptional({
    description:
      'Maximum distance (in meters) from specified origin/destination points',
    example: 5000,
    default: 5000,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1000) // Minimum search radius
  maxDistance?: number = 5000; // Default to 5km
}
