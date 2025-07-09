import { Transform } from 'class-transformer';
import {
  IsEmail,
  IsEnum,
  IsNotEmpty,
  IsOptional,
  IsString,
  MinLength,
  IsBoolean,
  Equals,
  IsPhoneNumber,
} from 'class-validator';
import { PASSWORD_PATTERN } from '../../../core/constants/base.constant';
import { UserGender } from 'src/core/enums/user.enum';
import { IsMatchPattern } from '../../../core/validators/IsMatchPattern.validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class BaseRegistrationDto {
  @ApiProperty({ description: "User's first name", minLength: 2 })
  @IsString()
  @IsNotEmpty()
  @MinLength(2)
  firstName: string;

  @ApiProperty({ description: "User's last name", minLength: 2 })
  @IsString()
  @IsNotEmpty()
  @MinLength(2)
  lastName: string;

  @ApiProperty({ description: "User's email address" })
  @IsEmail()
  @IsNotEmpty()
  @Transform(({ value }) => value?.toLowerCase().trim())
  email: string;

  @ApiProperty({
    description:
      "User's password - must contain uppercase, lowercase, and number",
    minLength: 8,
    pattern: PASSWORD_PATTERN,
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @IsMatchPattern(PASSWORD_PATTERN, {
    message:
      'Password must contain at least one uppercase letter, one lowercase letter, and one number',
  })
  password: string;

  @ApiPropertyOptional({
    description: 'Nigerian phone number',
    example: '+2348012345678',
  })
  @IsOptional()
  @IsPhoneNumber('NG', {
    message: 'Please provide a valid Nigerian phone number',
  })
  phoneNumber?: string;

  @ApiPropertyOptional({ description: "User's country" })
  @IsOptional()
  @IsString()
  country?: string;

  @ApiPropertyOptional({
    description: "User's gender",
    enum: UserGender,
  })
  @IsOptional()
  @IsEnum(UserGender)
  gender?: UserGender;

  @ApiProperty({
    description: 'Whether user has accepted terms and conditions',
    default: false,
  })
  @IsBoolean({ message: 'You must accept the terms and conditions.' })
  @Equals(true, { message: 'You must accept the terms and conditions.' })
  termsAccepted: boolean;
}
