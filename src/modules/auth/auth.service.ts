import { Injectable, Logger } from '@nestjs/common';
import {
  EMAIL_ALREADY_EXISTS,
  INVALID_CODE,
  INVALID_CODE_FORGOT_PASSWORD,
  INVALID_EMAIL_OR_PASSWORD,
  INVALID_USER,
  PORTAL_TYPE_ERROR,
} from 'src/core/constants/messages.constant';
import { EncryptHelper, ErrorHelper } from 'src/core/helpers';
import { UserLoginStrategy, IDriver, IPassenger } from 'src/core/interfaces';
import { PassengerRegistrationDto } from '../passenger/dto/passenger.dto';
import { DriverRegistrationDto } from '../driver/dto/driver-regidtration.dto';
import { UserService } from '../user/user.service';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Token } from '../user/schemas/token.schema';
import { MailEvent } from '../mail/mail.event';
import { UserSessionService } from 'src/global/user-session/service';
import { TokenHelper } from 'src/global/utils/token.utils';
import { PortalType } from 'src/core/enums/auth.enum';
import { UpdateUserDto } from './dto/update-user.dto';
import { AwsS3Service } from '../storage';
import { Role } from '../user/schemas/role.schema';
import { User } from '../user/schemas/user.schema';
import { IUser } from 'src/core/interfaces';
import { LoginDto } from './dto/auth.dto';
import { UserStatus } from 'src/core/enums/user.enum';

@Injectable()
export class AuthService {
  private logger = new Logger(AuthService.name);

  constructor(
    @InjectModel(Token.name) private tokenRepo: Model<Token>,
    @InjectModel(Role.name) private roleRepo: Model<Role>,
    @InjectModel(User.name) private userRepo: Model<User>,
    private userService: UserService,
    private mailEvent: MailEvent,
    private encryptHelper: EncryptHelper,
    private tokenHelper: TokenHelper,
    private userSessionService: UserSessionService,
    private awsS3Service: AwsS3Service,
  ) {}

  async createPortalUser(
    payload: DriverRegistrationDto | PassengerRegistrationDto,
    portalType: PortalType,
  ): Promise<any> {
    try {
      const user = await this.createUser(payload, {
        strategy: UserLoginStrategy.LOCAL,
        portalType,
      });

      const tokenInfo = await this.generateUserSession(user);

      return {
        token: tokenInfo,
        user: user,
      };
    } catch (error) {
      ErrorHelper.ConflictException('Email Already Exist');
      this.logger.log('createPortalUser', { error });
    }
  }

  private async generateUserSession(
    user: IDriver | IPassenger,
    rememberMe = true,
  ) {
    const tokenInfo = this.tokenHelper.generate(user);

    await this.userSessionService.create(user, {
      sessionId: tokenInfo.sessionId,
      rememberMe,
    });

    return tokenInfo;
  }

  async createUser(
    payload: DriverRegistrationDto | PassengerRegistrationDto,
    options: {
      strategy: UserLoginStrategy;
      portalType: PortalType;
      adminCreated?: boolean;
    },
  ): Promise<IPassenger | IDriver> {
    const { email } = payload;
    const { strategy, portalType } = options;

    const emailQuery = {
      email: email.toLowerCase(),
    };

    if (!portalType) {
      ErrorHelper.BadRequestException(PORTAL_TYPE_ERROR);
    }

    const emailExist = await this.userRepo.findOne(emailQuery, {
      getDeleted: true,
    });

    if (emailExist) {
      ErrorHelper.BadRequestException(EMAIL_ALREADY_EXISTS);
    }

    const roleData = await this.roleRepo.findOne({ name: portalType });

    const user = await this.userRepo.create({
      email: payload.email.toLowerCase(),
      password: await this.encryptHelper.hash(payload.password),
      firstName: payload.firstName,
      lastName: payload.lastName,
      country: payload.country,
      strategy,
      emailConfirm: strategy === UserLoginStrategy.LOCAL ? false : true,
      portalType: portalType,
      roles: [roleData],
    });

    return { ...user.toObject(), _id: user._id.toString() };
  }

  async login(params: LoginDto) {
    try {
      const { email, password, portalType } = params;

      const user = await this.validateUser(email, password, portalType);

      const tokenInfo = await this.generateUserSession(user, params.rememberMe);

      await this.userRepo.updateOne(
        { _id: user._id },
        { lastSeen: new Date() },
      );

      return {
        token: tokenInfo,
        user,
      };
    } catch (error) {
      ErrorHelper.BadRequestException(error);
    }
  }

  async validateUser(
    email: string,
    password: string,
    portalType?: PortalType,
  ): Promise<IDriver | IPassenger> {
    const emailQuery = {
      email: email.toLowerCase(),
    };

    const user = await this.userRepo
      .findOne(emailQuery)
      .populate('roles', 'name');

    if (!user) {
      ErrorHelper.BadRequestException(INVALID_EMAIL_OR_PASSWORD);
    }

    const passwordMatch = await this.encryptHelper.compare(
      password,
      user.password,
    );
    if (!passwordMatch) {
      ErrorHelper.BadRequestException(INVALID_EMAIL_OR_PASSWORD);
    }

    if (user.status === UserStatus.INACTIVE) {
      ErrorHelper.BadRequestException('Your account is inactive');
    }

    const roleNames = user.roles.map((role) => role.name);

    if (!roleNames.includes(portalType as any)) {
      ErrorHelper.ForbiddenException(
        'Forbidden: You does not have the required role to access this route.',
      );
    }

    return { ...user.toObject(), _id: user._id.toString() };
  }

  async resendVerificationEmail(userId: string) {
    const user = await this.userRepo.findById(userId);

    if (!user) {
      ErrorHelper.BadRequestException('User not found');
    }

    if (user.emailConfirm) {
      ErrorHelper.BadRequestException('Email already confirmed');
    }

    const confirmationCode = await this.userService.generateOtpCode({
      ...user.toObject(),
      _id: user._id.toString(),
    });

    await this.mailEvent.sendUserConfirmation(user, confirmationCode);

    return user;
  }

  async forgotPassword(email: string, callbackURL: string) {
    const emailQuery = {
      email: email.toLowerCase(),
    };

    if (!callbackURL) {
      ErrorHelper.BadRequestException('Please input a valid callbackURL');
    }

    const user = await this.userRepo.findOne(emailQuery);

    if (!user) {
      ErrorHelper.BadRequestException('User does not exist');
    }

    const confirmationCode = await this.userService.generateOtpCode(
      { ...user.toObject(), _id: user._id.toString() },
      {
        numberOnly: false,
        length: 21,
      },
    );

    await this.mailEvent.sendResetPassword(user, confirmationCode, callbackURL);

    return {
      success: true,
    };
  }

  async resetPassword(code: string, password: string) {
    const token = await this.tokenRepo.findOne({ code });

    if (!token) {
      ErrorHelper.BadRequestException(INVALID_CODE_FORGOT_PASSWORD);
    }

    const user = await this.userRepo.findById(token.user);

    if (!user) {
      ErrorHelper.BadRequestException(INVALID_USER);
    }

    // Ensure new password is not the same as the old password
    const passwordMatch = await this.encryptHelper.compare(
      password,
      user.password,
    );
    if (passwordMatch) {
      ErrorHelper.BadRequestException(
        'New password cannot be the same as the previous password',
      );
    }

    await this.userService.verifyOtpCode(
      { ...user.toObject(), _id: user._id.toString() },
      code,
    );

    const hashedPassword = await this.encryptHelper.hash(password);

    await this.userRepo.findByIdAndUpdate(user._id, {
      password: hashedPassword,
      hasChangedPassword: true, // Mark password as changed
    });

    return {
      success: true,
    };
  }

  async verifyUserEmail(userId: string, code: string) {
    const errorMessage = 'OTP has expired';

    const user = await this.userRepo.findById(userId);

    if (!user) {
      ErrorHelper.BadRequestException('User not found');
    }

    await this.userService.verifyOtpCode(
      { ...user.toObject(), _id: user._id.toString() },
      code,
      errorMessage,
    );

    const updatedUser = await this.userRepo.findByIdAndUpdate(
      user._id,
      { emailConfirm: true },
      { new: true },
    );

    return updatedUser;
  }

  async logoutUser(userId: string) {
    return await this.userService.logout(userId);
  }

  async tCodeLogin(code: string) {
    const token = await this.tokenRepo.findOne({ code });

    if (!token) {
      ErrorHelper.BadRequestException(INVALID_CODE);
    }

    let user = null;

    user = await this.userRepo.findById(token.user);

    if (!user) {
      ErrorHelper.BadRequestException(INVALID_USER);
    }

    await this.userService.verifyOtpCode(user.toObject(), code);
    const tokenInfo = await this.generateUserSession(user.toObject());

    return {
      token: tokenInfo,
      user: user.toObject(),
    };
  }

  async getAllUsers() {
    return await this.userRepo.find({});
  }

  async getUserInfo(email: string): Promise<IUser> {
    const user = await this.userRepo.findOne({ email });

    if (!user) {
      ErrorHelper.NotFoundException('No User Found.');
    }

    return { ...user.toJSON(), _id: user._id.toString() };
  }

  async updateUserInfo(
    userId: string,
    updateUserDto: UpdateUserDto,
  ): Promise<IDriver | IPassenger> {
    const updatedUser = await this.userRepo.findByIdAndUpdate(
      userId,
      { $set: updateUserDto },
      { new: true, runValidators: true },
    );

    if (!updatedUser) {
      ErrorHelper.NotFoundException(INVALID_USER);
    }

    return { ...updatedUser.toObject(), _id: updatedUser._id.toString() };
  }

  async uploadAvatar(userId: string, file: Express.Multer.File) {
    const user = await this.userRepo.findById(userId);

    if (!user) {
      ErrorHelper.NotFoundException('User not found');
    }

    if (!file) {
      ErrorHelper.BadRequestException('Image is required');
    }

    const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (!allowedMimeTypes.includes(file.mimetype)) {
      ErrorHelper.BadRequestException(
        'Unsupported file type. Please upload a JPEG, PNG, or GIF image.',
      );
    }

    const maxSizeInBytes = 5 * 1024 * 1024; // 5 MB
    if (file.size > maxSizeInBytes) {
      ErrorHelper.BadRequestException(
        'File size exceeds the maximum limit of 5 MB.',
      );
    }

    const uploadedUrl = await this.awsS3Service.uploadAttachment(file);

    await this.userRepo.findByIdAndUpdate(userId, { avatar: uploadedUrl });

    return { avatar: uploadedUrl };
  }

  async changePasswordConfirmation(
    user: IPassenger | IDriver,
    oldPassword: string,
  ) {
    const _user = await this.userRepo.findById(user._id);

    if (_user.strategy !== UserLoginStrategy.LOCAL && !_user.password) {
      ErrorHelper.ForbiddenException(
        'You can not change your password since you do not have one, please use the forgot password to get a password',
      );
    }

    const passwordMatch = await this.encryptHelper.compare(
      oldPassword,
      _user.password,
    );

    if (!passwordMatch) {
      ErrorHelper.BadRequestException('Please enter a valid current password');
    }

    const confirmationCode = await this.userService.generateOtpCode(user);

    await this.mailEvent.sendUserConfirmation(
      user as IDriver | IPassenger,
      confirmationCode,
    );

    return {
      success: true,
    };
  }

  async verifychangePasswordConfirmation(
    user: IDriver | IPassenger,
    code: string,
  ) {
    const errorMessage = 'OTP has expired’';

    await this.userService.verifyOtpCode(user, code, errorMessage);

    return {
      success: true,
    };
  }

  async updatePassword(user: IDriver | IPassenger, password: string) {
    const userDoc = await this.userRepo.findById(user._id);

    const hashedPassword = await this.encryptHelper.hash(password);
    userDoc.password = hashedPassword;

    await this.userRepo.updateOne(
      {
        _id: user._id,
      },
      {
        password: hashedPassword,
        hasChangedPassword: true,
      },
    );
  }

  async getAllRoles() {
    return await this.roleRepo.find({});
  }

  async getAllUserRoles() {
    return await this.userRepo.find().populate('roles');
  }

  async sessionExists(params: LoginDto): Promise<{
    exists: boolean;
    user: IDriver | IPassenger;
  }> {
    const { email, password } = params;

    const user = await this.validateUser(email, password);

    const session = await this.userSessionService.checkSession(user._id);

    return {
      exists: !!session,
      user,
    };
  }
}
