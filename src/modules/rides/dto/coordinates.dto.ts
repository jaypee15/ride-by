import { ApiProperty } from '@nestjs/swagger';
import { IsLatitude, IsLongitude, IsNotEmpty } from 'class-validator';

export class CoordinatesDto {
  @ApiProperty({ example: 6.5244, description: 'Latitude' })
  @IsLatitude()
  @IsNotEmpty()
  lat: number;

  @ApiProperty({ example: 3.3792, description: 'Longitude' })
  @IsLongitude()
  @IsNotEmpty()
  lon: number;
}
