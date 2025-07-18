import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
  Logger,
  UseInterceptors,
  UploadedFile,
  Patch,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import {
  EmailConfirmationDto,
  ForgotPasswordDto,
  // TCodeLoginDto,
} from './dto';
import { IDriver, IPassenger } from 'src/core/interfaces';
import { User as UserDecorator } from 'src/core/decorators';
import { AuthGuard } from 'src/core/guards';
import { SecretsService } from 'src/global/secrets/service';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiBody,
  ApiConsumes,
} from '@nestjs/swagger';
import { AuthUserResponseDto, BaseResponseDto } from './dto/auth-response.dto';
import { SendEmailOtpDto } from './dto/send-email-otp.dto';
import { VerifyEmailOtpDto } from './dto/verify-email-otp.dto';
import { CompleteProfileDto } from './dto/complete-profile.dto';
import { User } from 'src/core/decorators';
import {
  LoginWithPhoneOtpDto,
  SendLoginOtpToPhoneDto,
} from './dto/login-phone-otp.dto';
import { LoginWithEmailAndPhoneDto } from './dto/login-email.dto';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  private logger = new Logger(AuthController.name);
  constructor(
    private authService: AuthService,
    private secretSecret: SecretsService,
  ) {}

  @Post('email/send-otp')
  @ApiOperation({
    summary: 'Send OTP to the provided email address for signup/verification',
  })
  @ApiResponse({ status: 200, description: 'Email OTP sent successfully.' })
  @ApiResponse({
    status: 409,
    description: 'Email already exists and is verified.',
  })
  @HttpCode(HttpStatus.OK)
  async sendEmailOtp(
    @Body() body: SendEmailOtpDto,
  ): Promise<{ message: string }> {
    const data = await this.authService.sendEmailVerificationOtp(body);
    return { message: data.message };
  }

  @Post('email/verify-otp')
  @ApiOperation({
    summary: 'Verify OTP received via email',
    description:
      'On success, it returns a partial token to be used for completing the profile.',
  })
  @ApiResponse({
    status: 200,
    description: 'Email verified successfully.',
    schema: {
      properties: {
        message: { type: 'string' },
        data: {
          properties: {
            partialToken: { type: 'string' },
          },
        },
      },
    },
  })
  @ApiResponse({ status: 400, description: 'Invalid or expired OTP.' })
  @HttpCode(HttpStatus.OK)
  async verifyEmailOtp(
    @Body() body: VerifyEmailOtpDto,
  ): Promise<{ message: string; data: { partialToken: string } }> {
    const data = await this.authService.verifyEmailOtp(body);
    return { message: 'Email verified successfully', data };
  }

  // --- New Profile Completion Endpoint ---
  @Patch('profile/complete') // Use PATCH
  @UseGuards(AuthGuard) // Requires partial token
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Complete user profile after phone and email verification',
  })
  @ApiResponse({
    status: 200,
    description: 'Profile completed successfully. Returns full user session.',
    type: BaseResponseDto<AuthUserResponseDto>,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid input data.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Email not verified.',
  })
  async completeProfile(
    @User() partialUser: { _id: string },
    @Body() body: CompleteProfileDto,
  ): Promise<{ message: string; data: any }> {
    // Return full login response structure
    const result = await this.authService.completeUserProfile(
      partialUser._id,
      body,
    );
    return {
      message: 'Profile completed and user logged in successfully.',
      data: result, // Contains { token, user }
    };
  }

  // --- Email + Password +phone Login ---
  @Post('login/email')
  @ApiOperation({
    summary: 'Login user with email or phone number and password',
  })
  @ApiResponse({
    status: 200,
    description: 'Login successful',
    type: BaseResponseDto<AuthUserResponseDto>,
  })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  async loginWithEmail(@Body() loginDto: LoginWithEmailAndPhoneDto) {
    const data = await this.authService.loginWithEmailAndPhone(loginDto);
    return {
      data,
      message: 'Login successful',
    };
  }

  // --- Phone + OTP Login (Two-step: 1. Send OTP, 2. Verify OTP & Login) ---
  @Post('login/phone/send-otp')
  @ApiOperation({ summary: 'Send OTP to phone number for login' })
  @ApiResponse({ status: 200, description: 'OTP sent successfully' })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @HttpCode(HttpStatus.OK)
  async sendLoginOtpToPhone(@Body() dto: SendLoginOtpToPhoneDto) {
    await this.authService.sendLoginOtpToPhone(dto);
    return {
      message: 'Login OTP sent successfully to your phone number.',
    };
  }

  @Post('login/phone/verify-otp')
  @ApiOperation({ summary: 'Login user with phone number and OTP' })
  @ApiResponse({
    status: 200,
    description: 'Login successful',
    type: BaseResponseDto<AuthUserResponseDto>,
  })
  @ApiResponse({ status: 401, description: 'Invalid OTP or phone number' })
  async loginWithPhoneOtp(@Body() loginDto: LoginWithPhoneOtpDto) {
    const data = await this.authService.loginWithPhoneOtp(loginDto);
    return {
      data,
      message: 'Login successful',
    };
  }

  @UseGuards(AuthGuard)
  @Post('resend-verification')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Resend verification email' })
  @ApiResponse({
    status: 200,
    description: 'Verification code sent successfully',
    type: BaseResponseDto<{ sent: boolean }>,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async resendVerificationEmail(@UserDecorator() user: IDriver | IPassenger) {
    const data = await this.authService.resendVerificationEmail(user._id);

    return {
      data,
      message: 'Verification Code Sent Successfully',
    };
  }

  @HttpCode(HttpStatus.OK)
  @Post('/forgot-password')
  @ApiOperation({ summary: 'Request password reset' })
  @ApiResponse({
    status: 200,
    description: 'Password reset email sent',
    type: BaseResponseDto<{ sent: boolean }>,
  })
  @ApiResponse({ status: 404, description: 'User not found' })
  async forgotPassword(
    @Body() body: ForgotPasswordDto,
    @Body('callbackURL') query: string,
  ): Promise<object> {
    const data = await this.authService.forgotPassword(body.email, query);

    return {
      data,
      message: 'Password reset link has been sent to your email',
    };
  }

  @HttpCode(HttpStatus.OK)
  @Post('/reset-password')
  @ApiOperation({ summary: 'Reset password using code' })
  @ApiResponse({
    status: 200,
    description: 'Password changed successfully',
    type: BaseResponseDto<{ updated: boolean }>,
  })
  @ApiResponse({ status: 400, description: 'Invalid or expired code' })
  @ApiBody({
    schema: {
      properties: {
        code: { type: 'string', example: '123456' },
        password: { type: 'string', example: 'newPassword123' },
      },
    },
  })
  async resetPassword(
    @Body('code') code: string,
    @Body('password') password: string,
  ): Promise<object> {
    const data = await this.authService.resetPassword(code, password);

    return {
      data,
      message: 'Password Changed Successfully',
    };
  }

  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('/confirmation')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Verify email address' })
  @ApiResponse({
    status: 200,
    description: 'Email verified successfully',
    type: BaseResponseDto<AuthUserResponseDto>,
  })
  @ApiResponse({ status: 400, description: 'Invalid verification code' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async verifyEmail(
    @UserDecorator() user: IDriver | IPassenger,
    @Body() body: EmailConfirmationDto,
  ): Promise<object> {
    const data = await this.authService.verifyUserEmail(user._id, body.code);

    return {
      data,
      message: 'Email verified successfully',
    };
  }

  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('/logout')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Logout user' })
  @ApiResponse({
    status: 200,
    description: 'Logged out successfully',
    type: BaseResponseDto<{ loggedOut: boolean }>,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async logout(@UserDecorator() user: IDriver | IPassenger): Promise<object> {
    const data = await this.authService.logoutUser(user._id);

    return {
      data,
      message: 'Logout successfully',
    };
  }

  // @HttpCode(HttpStatus.OK)
  // @Post('/tcode-auth')
  // @ApiOperation({ summary: 'Authenticate using temporary code' })
  // @ApiResponse({ status: 200, description: 'Authentication successful' })
  // @ApiResponse({ status: 401, description: 'Invalid code' })
  // async tCodeAuth(@Body() body: TCodeLoginDto) {
  //   const data = await this.authService.tCodeLogin(body.tCode);

  //   return {
  //     data,
  //     message: 'Authenticated successfully',
  //   };
  // }

  // @HttpCode(HttpStatus.OK)
  // @Post('/tcode_auth')
  // async tCodeAuthU(@Body() body: TCodeLoginDto) {
  //   return this.tCodeAuth(body);
  // }

  @HttpCode(HttpStatus.OK)
  @UseGuards(AuthGuard)
  @Get('/all-users')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get all users' })
  @ApiResponse({
    status: 200,
    description: 'Users fetched successfully',
    type: BaseResponseDto<AuthUserResponseDto[]>,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getAllUsers() {
    const data = await this.authService.getAllUsers();

    return {
      data,
      message: 'Users Fetched Successfully',
    };
  }

  @HttpCode(HttpStatus.OK)
  @Get('/user')
  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get current user info' })
  @ApiResponse({
    status: 200,
    description: 'User info fetched successfully',
    type: BaseResponseDto<AuthUserResponseDto>,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getUser(@UserDecorator() user: IDriver | IPassenger): Promise<object> {
    const data = await this.authService.getUserInfo(user.email);

    return {
      data,
      message: 'User Info Fetched Successfully',
    };
  }

  @UseGuards(AuthGuard)
  @UseInterceptors(FileInterceptor('avatar'))
  @Post('/user/upload-avatar')
  @ApiBearerAuth()
  @ApiConsumes('multipart/form-data')
  @ApiOperation({ summary: 'Upload user avatar' })
  @ApiResponse({
    status: 200,
    description: 'Avatar uploaded successfully',
    type: BaseResponseDto<AuthUserResponseDto>,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        avatar: {
          type: 'string',
          format: 'binary',
        },
      },
    },
  })
  async uploadAvatar(
    @UserDecorator() user: IDriver | IPassenger,
    @UploadedFile() file: Express.Multer.File,
  ) {
    const data = await this.authService.uploadAvatar(user._id, file);

    return {
      data,
      message: 'Avatar uploaded successfully',
    };
  }

  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('/change-password-confirmation')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Request password change confirmation' })
  @ApiResponse({
    status: 200,
    description: 'Confirmation code sent successfully',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async changePasswordConfirmation(
    @UserDecorator() user: IDriver | IPassenger,
    @Body('oldPassword') body: string,
  ): Promise<object> {
    const data = await this.authService.changePasswordConfirmation(user, body);

    return {
      data,
      message: 'Change Password Confirmation Sent Successfully',
    };
  }

  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('/verify-password-confirmation')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Verify password change confirmation code' })
  @ApiResponse({ status: 200, description: 'Code verified successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async verifychangePasswordConfirmation(
    @UserDecorator() user: IDriver | IPassenger,
    @Body('code') code: string,
  ): Promise<object> {
    const data = await this.authService.verifychangePasswordConfirmation(
      user,
      code,
    );

    return {
      data,
      message: 'Change Password Confirmation Sent Successfully',
    };
  }

  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('/change-password')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Change user password' })
  @ApiResponse({ status: 200, description: 'Password changed successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async updatePassword(
    @UserDecorator() user: IDriver | IPassenger,
    @Body('password') password: string,
  ): Promise<object> {
    const data = await this.authService.updatePassword(user, password);

    return {
      data,
      message: 'Password Changed Successfully',
    };
  }

  @HttpCode(HttpStatus.OK)
  @Get('/roles')
  @ApiOperation({ summary: 'Get all roles' })
  @ApiResponse({ status: 200, description: 'Roles fetched successfully' })
  async getAllRoles(): Promise<object> {
    const data = await this.authService.getAllRoles();

    return {
      data,
      message: 'All Roles Successfully',
    };
  }

  @HttpCode(HttpStatus.OK)
  @Get('/users')
  @ApiOperation({ summary: 'Get all users with their roles' })
  @ApiResponse({
    status: 200,
    description: 'Users with roles fetched successfully',
  })
  async getAllUsersAndRoles(): Promise<object> {
    const data = await this.authService.getAllUserRoles();

    return {
      data,
      message: 'All Users Successfully',
    };
  }
}
