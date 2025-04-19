import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsArray,
  IsDateString,
  //   IsLatitude,
  //   IsLongitude,
  IsMongoId,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsString,
  Min,
  ValidateNested,
  ArrayMaxSize,
} from 'class-validator';
import { CoordinatesDto } from './coordinates.dto';

export class CreateRideDto {
  @ApiProperty({
    description: 'ID of the vehicle to be used for the ride',
    example: '605c72ef4e79a3a3e8f2d3b4',
  })
  @IsMongoId()
  @IsNotEmpty()
  vehicleId: string;

  @ApiProperty({ description: 'Origin coordinates', type: CoordinatesDto })
  @ValidateNested()
  @Type(() => CoordinatesDto)
  @IsNotEmpty()
  origin: CoordinatesDto;

  @ApiProperty({ description: 'Destination coordinates', type: CoordinatesDto })
  @ValidateNested()
  @Type(() => CoordinatesDto)
  @IsNotEmpty()
  destination: CoordinatesDto;

  @ApiProperty({
    description: 'User-friendly origin address',
    example: '123 Main St, Ikeja, Lagos',
  })
  @IsString()
  @IsNotEmpty()
  originAddress: string;

  @ApiProperty({
    description: 'User-friendly destination address',
    example: '456 University Rd, Ibadan',
  })
  @IsString()
  @IsNotEmpty()
  destinationAddress: string;

  // Optional: Waypoints might be added later or via a separate update endpoint
  // @ApiPropertyOptional({ description: 'Waypoint coordinates', type: [CoordinatesDto] })
  // @IsOptional()
  // @IsArray()
  // @ValidateNested({ each: true })
  // @Type(() => CoordinatesDto)
  // waypoints?: CoordinatesDto[];

  @ApiProperty({
    description: 'Departure date and time (ISO 8601 format)',
    example: '2025-08-15T09:00:00.000Z',
  })
  @IsDateString()
  @IsNotEmpty()
  departureTime: string; // Receive as string, convert to Date in service

  @ApiProperty({
    description: 'Price per seat in NGN (or smallest currency unit)',
    example: 2500,
  })
  @IsNumber()
  @Min(0) // Allow free rides? Or set Min(100)?
  @IsNotEmpty()
  pricePerSeat: number;

  @ApiPropertyOptional({
    type: [String],
    example: ['No Smoking', 'Music allowed'],
    description: 'List of ride preferences',
  })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  @ArrayMaxSize(10)
  preferences?: string[];
}
