import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { IsLatitude, IsLongitude, IsNotEmpty } from 'class-validator';

export class CoordinatesDto {
  @ApiProperty({ example: 6.5244, description: 'Latitude' })
  @Type(() => Number)
  @IsLatitude()
  @IsNotEmpty()
  lat: number;

  @ApiProperty({ example: 3.3792, description: 'Longitude' })
  @Type(() => Number)
  @IsLongitude()
  @IsNotEmpty()
  lon: number;
}
