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
} from '@nestjs/common';
import { AuthService } from './auth.service';
import {
  EmailConfirmationDto,
  ForgotPasswordDto,
  LoginDto,
  TCodeLoginDto,
} from './dto';
import { BaseRegistrationDto } from './dto/base-registeration.dto';
import { IDriver, IPassenger } from 'src/core/interfaces';
import { User as UserDecorator } from 'src/core/decorators';
import { AuthGuard } from 'src/core/guards';
import { SecretsService } from 'src/global/secrets/service';
import { PortalType } from 'src/core/enums/auth.enum';
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

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  private logger = new Logger(AuthController.name);
  constructor(
    private authService: AuthService,
    private secretSecret: SecretsService,
  ) {}

  @Post('/create-user')
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({
    status: 201,
    description: 'User successfully created',
    type: BaseResponseDto<AuthUserResponseDto>,
  })
  @ApiResponse({ status: 400, description: 'Bad request - Invalid input' })
  async register(
    @Body() body: BaseRegistrationDto,
    @Body('portalType') portalType: PortalType,
  ) {
    const data = await this.authService.createPortalUser(body, portalType);

    return {
      data,
      message: 'User created successfully',
    };
  }

  @Post('login')
  @ApiOperation({ summary: 'Login user' })
  @ApiResponse({
    status: 200,
    description: 'Login successful',
    type: BaseResponseDto<AuthUserResponseDto>,
  })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  async login(@Body() loginDto: LoginDto) {
    const data = await this.authService.login(loginDto);

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
  @Get('/logout')
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

  @HttpCode(HttpStatus.OK)
  @Post('/tcode-auth')
  @ApiOperation({ summary: 'Authenticate using temporary code' })
  @ApiResponse({ status: 200, description: 'Authentication successful' })
  @ApiResponse({ status: 401, description: 'Invalid code' })
  async tCodeAuth(@Body() body: TCodeLoginDto) {
    const data = await this.authService.tCodeLogin(body.tCode);

    return {
      data,
      message: 'Authenticated successfully',
    };
  }

  @HttpCode(HttpStatus.OK)
  @Post('/tcode_auth')
  async tCodeAuthU(@Body() body: TCodeLoginDto) {
    return this.tCodeAuth(body);
  }

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
