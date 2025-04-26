import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class RegisterDeviceDto {
  @ApiProperty({ description: 'FCM device registration token' })
  @IsString()
  @IsNotEmpty()
  deviceToken: string;
}
