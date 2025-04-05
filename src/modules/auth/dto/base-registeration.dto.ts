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
  IsPhoneNumber, // Import if you have a specific validator package or use IsMatchPattern
} from 'class-validator';
import { PASSWORD_PATTERN } from '../../../core/constants/base.constant';
import { UserGender } from 'src/core/enums/user.em';
import { IsMatchPattern } from '../../../core/validators/IsMatchPattern.validator';

export class BaseRegistrationDto {
  @IsString()
  @IsNotEmpty()
  @MinLength(2)
  firstName: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(2)
  lastName: string;

  @IsEmail()
  @IsNotEmpty()
  @Transform(({ value }) => value?.toLowerCase().trim())
  email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @IsMatchPattern(PASSWORD_PATTERN, {
    message:
      'Password must contain at least one uppercase letter, one lowercase letter, and one number',
  })
  password: string;

  // Consider adding password confirmation if needed on the frontend
  // @IsString()
  // @IsNotEmpty()
  // @Match('password', { message: 'Passwords do not match' }) // You might need a custom 'Match' validator or check in service
  // passwordConfirmation: string;

  @IsOptional()
  @IsPhoneNumber('NG', {
    message: 'Please provide a valid Nigerian phone number',
  }) // Use 'NG' if validator supports it, otherwise use regex via IsMatchPattern
  // Example Regex (adjust as needed for Nigerian formats like 080..., +23480...):
  // @IsMatchPattern(/^(\+234|0)[789][01]\d{8}$/, { message: 'Invalid Nigerian phone number format' })
  phoneNumber?: string;

  @IsOptional()
  @IsString()
  country?: string;

  @IsOptional()
  @IsEnum(UserGender)
  gender?: UserGender;

  @IsBoolean({ message: 'You must accept the terms and conditions.' })
  @Equals(true, { message: 'You must accept the terms and conditions.' })
  termsAccepted: boolean;
}
