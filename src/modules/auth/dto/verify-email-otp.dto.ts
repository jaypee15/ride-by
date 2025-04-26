import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';
import { Transform } from 'class-transformer';

export class VerifyEmailOtpDto {
  @ApiProperty({
    description: "User's email address being verified",
    example: 'user@example.com',
  })
  @IsEmail()
  @IsNotEmpty()
  @Transform(({ value }) => value?.toLowerCase().trim())
  email: string; // Include email to ensure OTP matches the intended address

  @ApiProperty({
    description: '6-digit OTP received via email',
    example: '123456',
  })
  @IsString()
  @IsNotEmpty()
  @Length(6, 6, { message: 'OTP must be exactly 6 digits' }) // Or match your email OTP length
  otp: string;
}
