import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsEmail,
  IsEnum,
  IsNotEmpty,
  IsOptional,
  IsString,
  MinLength,
  IsBoolean,
  IsPhoneNumber,
} from 'class-validator';
import { PortalType } from 'src/core/enums/auth.enum';
import { PASSWORD_PATTERN } from 'src/core/constants'; // Assuming you might want password pattern validation
import { IsMatchPattern } from 'src/core/validators';

export class LoginWithEmailDto {
  @ApiProperty({
    description: "User's email address",
    example: 'user@example.com',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({ description: "User's password" })
  @IsString()
  @IsNotEmpty()
  @MinLength(8) // Add if you want to enforce min length on login DTO too
  @IsMatchPattern(PASSWORD_PATTERN) // Optional: for consistency
  password: string;

  @ApiPropertyOptional({
    description:
      'Type of portal user is accessing. If omitted, defaults to PASSENGER.',
    enum: PortalType,
  })
  @IsEnum(PortalType)
  @IsOptional()
  portalType?: PortalType;

  @ApiPropertyOptional({
    description: 'Whether to keep user logged in',
    default: false,
  })
  @IsOptional()
  @IsBoolean()
  rememberMe?: boolean = false;
}

export class LoginWithEmailAndPhoneDto {
  @ApiProperty({
    description: "User's email address",
    example: 'user@example.com',
  })
  @IsEmail()
  @IsNotEmpty()
  @IsOptional()
  email: string;

  @ApiProperty({
    description: "User's phone number",
    example: '+2348012345678',
  })
  @IsPhoneNumber('NG', {
    message: 'Please provide a valid Nigerian phone number',
  })
  @IsOptional()
  phoneNumber: string;

  @ApiProperty({ description: "User's password" })
  @IsString()
  @IsNotEmpty()
  @MinLength(8) // Add if you want to enforce min length on login DTO too
  @IsMatchPattern(PASSWORD_PATTERN) // Optional: for consistency
  password: string;

  @ApiProperty({
    description: 'Type of portal user is accessing',
    enum: PortalType,
  })
  @IsOptional()
  portalType: PortalType;

  @ApiPropertyOptional({
    description: 'Whether to keep user logged in',
    default: false,
  })
  @IsOptional()
  @IsBoolean()
  rememberMe?: boolean = false;
}
