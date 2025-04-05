import {
  IsBoolean,
  IsEmail,
  IsEnum,
  IsOptional,
  IsString,
  IsUrl,
} from 'class-validator';
import { PortalType } from 'src/core/enums/auth.enum';

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
