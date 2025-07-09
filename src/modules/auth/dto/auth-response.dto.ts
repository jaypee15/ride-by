import { ApiProperty } from '@nestjs/swagger';

export class BaseResponseDto<T> {
  @ApiProperty({ description: 'Response message' })
  message: string;

  @ApiProperty({ description: 'Response data' })
  data: T;
}

export class AuthUserResponseDto {
  @ApiProperty({ description: 'User ID' })
  _id: string;

  @ApiProperty({ description: 'Email address' })
  email: string;

  @ApiProperty({ description: 'First name' })
  firstName: string;

  @ApiProperty({ description: 'Last name' })
  lastName: string;

  @ApiProperty({ description: 'Profile avatar URL', required: false })
  avatar?: string;

  @ApiProperty({ description: 'About section', required: false })
  about?: string;

  @ApiProperty({ description: 'Country', required: false })
  country?: string;

  @ApiProperty({ description: 'Phone number', required: false })
  phoneNumber?: string;

  @ApiProperty({ description: 'Email confirmation status' })
  emailConfirm: boolean;

  @ApiProperty({ description: 'Account creation date' })
  createdAt: Date;

  @ApiProperty({ description: 'Last seen date' })
  lastSeen: Date;
}
