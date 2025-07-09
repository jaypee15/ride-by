import { IsNotEmpty, IsPhoneNumber, IsString, Length } from 'class-validator';

export class SendPhoneOtpDto {
  @IsString()
  @IsNotEmpty()
  @IsPhoneNumber('NG', {
    message:
      'Please provide a valid Nigerian phone number in E.164 format (e.g., +23480...)',
  })
  phoneNumber: string; // Expecting E.164 format (e.g., +2348012345678)
}

export class VerifyPhoneOtpDto {
  @IsString()
  @IsNotEmpty()
  @IsPhoneNumber('NG', {
    message:
      'Please provide a valid Nigerian phone number in E.164 format (e.g., +23480...)',
  })
  phoneNumber: string; // Expecting E.164 format

  @IsString()
  @IsNotEmpty()
  @Length(6, 6, { message: 'OTP must be exactly 6 digits' }) // Assuming 6-digit OTP
  otp: string;
}
