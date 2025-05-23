import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsEmail,
  IsEnum,
  IsNotEmpty,
  IsOptional,
  IsString,
  MinLength,
  IsBoolean,
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

  @ApiProperty({
    description: 'Type of portal user is accessing',
    enum: PortalType,
  })
  @IsEnum(PortalType)
  @IsNotEmpty()
  portalType: PortalType;

  @ApiPropertyOptional({
    description: 'Whether to keep user logged in',
    default: false,
  })
  @IsOptional()
  @IsBoolean()
  rememberMe?: boolean = false;
}
