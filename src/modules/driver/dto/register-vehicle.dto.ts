import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsArray,
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  Min,
  Max,
  MinLength,
  MaxLength,
  IsUppercase, // For plate number potentially
  ArrayMaxSize,
} from 'class-validator';

export class RegisterVehicleDto {
  @ApiProperty({ example: 'Toyota', description: 'Make of the vehicle' })
  @IsString()
  @IsNotEmpty()
  @MinLength(2)
  @MaxLength(50)
  make: string;

  @ApiProperty({ example: 'Camry', description: 'Model of the vehicle' })
  @IsString()
  @IsNotEmpty()
  @MinLength(1)
  @MaxLength(50)
  model: string;

  @ApiProperty({ example: 2018, description: 'Year of manufacture' })
  @IsInt()
  @Min(1980) // Adjust range as needed
  @Max(new Date().getFullYear()) // Cannot be newer than current year
  year: number;

  @ApiProperty({ example: 'Blue', description: 'Color of the vehicle' })
  @IsString()
  @IsNotEmpty()
  @MaxLength(30)
  color: string;

  @ApiProperty({
    example: 'ABC123XY',
    description: 'Vehicle plate number (unique)',
  })
  @IsString()
  @IsNotEmpty()
  @IsUppercase() // Optional: Enforce uppercase if desired
  @MaxLength(15) // Adjust max length
  plateNumber: string;

  @ApiProperty({
    example: 4,
    description: 'Number of seats available for passengers (excluding driver)',
  })
  @IsInt()
  @Min(1)
  @Max(10) // Set a reasonable max
  seatsAvailable: number;

  @ApiPropertyOptional({
    type: [String],
    example: ['Air Conditioning', 'USB Port'],
    description: 'List of vehicle features/amenities',
  })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  @ArrayMaxSize(10) // Limit number of features
  features?: string[];
}
