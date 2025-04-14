import {
  IsBoolean,
  IsEmail,
  IsEnum,
  IsOptional,
  IsString,
  IsUrl,
} from 'class-validator';
import { PortalType } from 'src/core/enums/auth.enum';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class EmailConfirmationDto {
  @ApiProperty({ description: 'Email verification code' })
  @IsString()
  code: string;
}

export class TCodeLoginDto {
  @ApiProperty({ description: 'Temporary authentication code' })
  @IsString()
  tCode: string;

  @ApiProperty({
    description: 'Type of portal user is accessing',
    enum: PortalType,
  })
  @IsString()
  portalType: PortalType;
}

export class CallbackURLDto {
  @ApiPropertyOptional({
    description: 'URL to redirect after action',
    required: false,
  })
  @IsUrl({ require_tld: false })
  @IsOptional()
  callbackURL: string;
}

export class RefreshTokenDto {
  @ApiProperty({ description: 'Refresh token for getting new access token' })
  @IsString()
  token: string;
}

export class ForgotPasswordDto {
  @ApiProperty({
    description: 'Email address for password reset',
    example: 'user@example.com',
  })
  @IsString()
  @IsEmail()
  email: string;
}

export class LoginDto {
  @ApiProperty({
    description: "User's email address",
    example: 'user@example.com',
  })
  @IsString()
  @IsEmail()
  email: string;

  @ApiProperty({ description: "User's password" })
  @IsString()
  password: string;

  @ApiProperty({
    description: 'Type of portal user is accessing',
    enum: PortalType,
  })
  @IsEnum(PortalType)
  portalType: PortalType;

  @ApiPropertyOptional({
    description: 'Whether to keep user logged in',
    default: false,
  })
  @IsOptional()
  @IsBoolean()
  rememberMe = false;
}
