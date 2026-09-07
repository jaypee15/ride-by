import { ApiProperty } from '@nestjs/swagger';
import { IsMongoId, IsNotEmpty } from 'class-validator';

export class AddFavoriteDriverDto {
  @ApiProperty({ description: 'Driver user id to favorite', example: '605c72ef4e79a3a3e8f2d3b4' })
  @IsMongoId()
  @IsNotEmpty()
  driverId: string;
}
