import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsEnum,
  IsNotEmpty,
  IsOptional,
  IsPhoneNumber,
  IsString,
  Length,
  IsBoolean,
} from 'class-validator';
import { PortalType } from 'src/core/enums/auth.enum';

export class SendLoginOtpToPhoneDto {
  @ApiProperty({
    description: 'Phone number in E.164 format',
    example: '+2348012345678',
  })
  @IsPhoneNumber('NG', {
    message: 'Please provide a valid Nigerian phone number',
  })
  @IsNotEmpty()
  phoneNumber: string;

  @ApiProperty({
    description: 'Type of portal user is accessing',
    enum: PortalType,
  })
  @IsEnum(PortalType)
  @IsNotEmpty()
  portalType: PortalType;
}

export class LoginWithPhoneOtpDto {
  // For completing login with OTP
  @ApiProperty({
    description: 'Phone number in E.164 format',
    example: '+2348012345678',
  })
  @IsPhoneNumber('NG', {
    message: 'Please provide a valid Nigerian phone number',
  })
  @IsNotEmpty()
  phoneNumber: string;

  @ApiProperty({ description: '6-digit OTP code', example: '123456' })
  @IsString()
  @IsNotEmpty()
  @Length(6, 6, { message: 'OTP must be exactly 6 digits' })
  otp: string;

  @ApiProperty({
    description: 'Type of portal user is accessing',
    enum: PortalType,
  })
  @IsEnum(PortalType)
  @IsNotEmpty()
  portalType: PortalType; // Keep portalType for consistency and validation

  @ApiPropertyOptional({
    description: 'Whether to keep user logged in',
    default: false,
  })
  @IsOptional()
  @IsBoolean()
  rememberMe?: boolean = false;
}
