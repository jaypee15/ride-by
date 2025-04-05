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

@Controller('auth')
export class AuthController {
  private logger = new Logger(AuthController.name);
  constructor(
    private authService: AuthService,
    private secretSecret: SecretsService,
  ) {}

  @Post('/create-user')
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
  async login(@Body() loginDto: LoginDto) {
    const data = await this.authService.login(loginDto);

    return {
      data,
      message: 'Login successful',
    };
  }

  @UseGuards(AuthGuard)
  @Post('resend-verification')
  async resendVerificationEmail(@UserDecorator() user: IDriver | IPassenger) {
    const data = await this.authService.resendVerificationEmail(user._id);

    return {
      data,
      message: 'Verification Code Sent Successfully',
    };
  }

  @HttpCode(HttpStatus.OK)
  @Post('/forgot-password')
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
  async logout(@UserDecorator() user: IDriver | IPassenger): Promise<object> {
    const data = await this.authService.logoutUser(user._id);

    return {
      data,
      message: 'Logout successfully',
    };
  }

  // delicate
  @HttpCode(HttpStatus.OK)
  @Get('/sync-users')
  async syncUsers() {
    const data = await this.authService.syncUsers();

    return {
      data,
      message: 'Users Synced successfully',
    };
  }

  @HttpCode(HttpStatus.OK)
  @Post('/tcode-auth')
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
  async getAllRoles(): Promise<object> {
    const data = await this.authService.getAllRoles();

    return {
      data,
      message: 'All Roles Successfully',
    };
  }

  @HttpCode(HttpStatus.OK)
  @Get('/users')
  async getAllUsersAndRoles(): Promise<object> {
    const data = await this.authService.getAllUserRoles();

    return {
      data,
      message: 'All Users Successfully',
    };
  }
}
