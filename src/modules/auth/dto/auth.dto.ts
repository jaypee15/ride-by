import {
  IsBoolean,
  IsEmail,
  IsEnum,
  IsObject,
  IsOptional,
  IsString,
  IsUrl,
} from 'class-validator';
import { PASSWORD_PATTERN } from 'src/core/constants';
import { PortalType } from 'src/core/enums/auth.enum';
import { IsMatchPattern } from 'src/core/validators';

export class EmailConfirmationDto {
  @IsString()
  code: string;
}

export class TCodeLoginDto {
  @IsString()
  tCode: string;

  @IsString()
  portalType: PortalType;
}

export class CallbackURLDto {
  @IsUrl({ require_tld: false })
  @IsOptional()
  callbackURL: string;
}

export class RefreshTokenDto {
  @IsString()
  token: string;
}

export class ForgotPasswordDto {
  @IsString()
  @IsEmail()
  email: string;
}

export class AuthDto {
  @IsString()
  @IsOptional()
  firstName: string;

  @IsString()
  @IsOptional()
  lastName: string;

  @IsString()
  @IsEmail()
  email: string;

  @IsString()
  @IsMatchPattern(PASSWORD_PATTERN)
  password: string;
}

export class XternCareerPath {
  @IsString()
  email: string;

  @IsOptional()
  @IsString()
  reasonToJoin?: string;

  @IsString()
  @IsOptional()
  profession?: string;

  @IsString()
  @IsOptional()
  pathway?: string;

  @IsObject()
  @IsOptional()
  techStacks?: object;

  @IsString()
  @IsOptional()
  assessmentScore?: string;
}

export class LoginDto {
  @IsString()
  @IsEmail()
  email: string;

  @IsString()
  password: string;

  @IsEnum(PortalType)
  portalType: PortalType;

  @IsOptional()
  @IsBoolean()
  rememberMe = false;
}
