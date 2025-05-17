import { Injectable, Logger } from '@nestjs/common';
import {
  EMAIL_ALREADY_EXISTS,
  INVALID_CODE,
  INVALID_CODE_FORGOT_PASSWORD,
  INVALID_EMAIL_OR_PASSWORD,
  INVALID_USER,
  PORTAL_TYPE_ERROR,
  INVALID_PHONE_NUMBER_OR_PASSWORD,
} from 'src/core/constants/messages.constant';
import { EncryptHelper, ErrorHelper } from 'src/core/helpers';
import { UserLoginStrategy, IDriver, IPassenger } from 'src/core/interfaces';
import { PassengerRegistrationDto } from '../passenger/dto/passenger.dto';
import { DriverRegistrationDto } from '../driver/dto/driver-registration.dto';
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
import { TwilioService } from '../twilio/twilio.service';
import { SendPhoneOtpDto, VerifyPhoneOtpDto } from './dto/send-phone-otp.dto';
import { SendEmailOtpDto } from './dto/send-email-otp.dto';
import { VerifyEmailOtpDto } from './dto/verify-email-otp.dto';
import { CompleteProfileDto } from './dto/complete-profile.dto';
import { RoleNameEnum } from 'src/core/interfaces';
import { SecretsService } from 'src/global/secrets/service';
import * as jwt from 'jsonwebtoken';

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
    private twilioService: TwilioService,
    private secretsService: SecretsService,
  ) {}

  async sendPhoneVerificationOtp(
    dto: SendPhoneOtpDto,
  ): Promise<{ message: string }> {
    const { phoneNumber } = dto;

    // 1. Check if phone number is already registered and verified (optional but recommended)
    const existingVerifiedUser = await this.userRepo.findOne({
      phoneNumber,
      phoneVerified: true,
      status: { $ne: UserStatus.INACTIVE },
    }); // Check active/pending etc.
    if (existingVerifiedUser) {
      ErrorHelper.ConflictException(
        'This phone number is already linked to a verified account.',
      );
    }

    // 2. Send verification via Twilio Verify
    try {
      const sent = await this.twilioService.sendVerificationToken(
        phoneNumber,
        'sms',
      );
      if (sent) {
        return { message: 'Verification code sent successfully via SMS.' };
      } else {
        // Should not happen if sendVerificationToken throws on failure, but as fallback
        ErrorHelper.InternalServerErrorException(
          'Could not send verification code.',
        );
      }
    } catch (error) {
      // Error is already logged in TwilioService, rethrow specific message
      ErrorHelper.InternalServerErrorException(
        error.message || 'Could not send verification code.',
      );
    }
  }

  async verifyPhoneNumberOtp(
    dto: VerifyPhoneOtpDto,
  ): Promise<{ partialToken: string; message: string }> {
    const { phoneNumber, otp } = dto;
    let userId: string;

    // 1. Check verification using Twilio Verify
    const isApproved = await this.twilioService.checkVerificationToken(
      phoneNumber,
      otp,
    );
    if (!isApproved) {
      ErrorHelper.BadRequestException('Invalid or expired verification code.');
    }

    // 2. Check/Create User
    let user = await this.userRepo.findOne({ phoneNumber });

    if (user) {
      // User exists
      if (
        user.phoneVerified &&
        user.status !== UserStatus.PENDING_EMAIL_VERIFICATION
      ) {
        // Phone already verified and likely active/profile complete - maybe initiate login instead?
        // For now, let's prevent proceeding with signup flow.
        ErrorHelper.ConflictException(
          'Phone number already linked to a verified account. Please log in.',
        );
      }
      // User exists but phone wasn't verified, mark as verified
      user.phoneVerified = true;
      // Ensure status allows proceeding
      if (user.status !== UserStatus.PENDING_EMAIL_VERIFICATION) {
        user.status = UserStatus.PENDING_EMAIL_VERIFICATION;
      }
      await user.save();
      userId = user._id.toString();
      this.logger.log(`Updated existing user ${userId} - phone verified.`);
    } else {
      // No user exists, create one
      // Determine default role (e.g., Passenger)
      const defaultRole = await this.roleRepo.findOne({
        name: RoleNameEnum.Passenger,
      });
      if (!defaultRole) throw new Error('Default role not found'); // Internal config error

      user = await this.userRepo.create({
        phoneNumber: phoneNumber,
        phoneVerified: true,
        status: UserStatus.PENDING_EMAIL_VERIFICATION,
        roles: [defaultRole._id], // Assign default role
        // Other fields (email, password, name) are null/undefined initially
      });
      userId = user._id.toString();
      this.logger.log(`Created new user ${userId} after phone verification.`);
    }

    // 3. Generate Partial JWT
    // This token proves phone is verified and identifies the user for next steps
    const partialPayload = {
      _id: userId,
      phone: phoneNumber, // Include phone for reference if needed
      isPhoneVerified: true,
      isPartialToken: true, // Flag to distinguish from full login token
    };

    const jwtString = jwt.sign(
      partialPayload,
      this.secretsService.jwtSecret.JWT_SECRET,
      {
        expiresIn: '1h',
      },
    );

    return {
      message: 'Phone number verified successfully.',
      partialToken: jwtString, // Contains userId etc.
    };
  }

  // --- Email Verification ---

  async sendEmailVerificationOtp(
    userId: string,
    dto: SendEmailOtpDto,
  ): Promise<{ message: string }> {
    const { email } = dto;
    this.logger.log(
      `User ${userId} requesting email verification OTP for ${email}`,
    );

    // Optional: Check if email is already verified on *another* account
    const emailExists = await this.userRepo.findOne({
      email: email.toLowerCase(),
      _id: { $ne: userId },
      emailConfirm: true,
    });
    if (emailExists) {
      ErrorHelper.ConflictException(
        'This email address is already linked to another verified account.',
      );
    }

    const user = await this.userRepo.findById(userId);
    if (!user) ErrorHelper.NotFoundException('User not found.'); // Should not happen with valid partial JWT
    if (!user.phoneVerified)
      ErrorHelper.ForbiddenException('Phone number must be verified first.'); // Belt-and-suspenders check

    // Generate and send email OTP using existing UserService logic
    try {
      const emailOtp = await this.userService.generateOtpCode({
        _id: userId,
      } as IUser); // Pass minimal user object
      await this.mailEvent.sendUserConfirmation(
        { email, firstName: user.firstName || 'User' },
        emailOtp,
      ); // Pass email and name
      this.logger.log(
        `Sent email verification OTP to ${email} for user ${userId}`,
      );
      return { message: 'Verification code sent to your email.' };
    } catch (error) {
      this.logger.error(
        `Failed to send email OTP for user ${userId}: ${error.message}`,
        error.stack,
      );
      ErrorHelper.InternalServerErrorException(
        'Could not send email verification code.',
      );
    }
  }

  async verifyEmailOtp(
    userId: string,
    dto: VerifyEmailOtpDto,
  ): Promise<{ message: string }> {
    const { email, otp } = dto;
    this.logger.log(
      `User ${userId} attempting to verify email ${email} with OTP`,
    );

    const user = await this.userRepo.findById(userId);
    if (!user) ErrorHelper.NotFoundException('User not found.');
    if (!user.phoneVerified)
      ErrorHelper.ForbiddenException('Phone number must be verified first.');

    // Verify email OTP using UserService
    const isEmailOtpValid = await this.userService.verifyOtpCode(
      { _id: userId } as IUser,
      otp,
      'Invalid or expired email verification code.',
    );
    if (!isEmailOtpValid) {
      // verifyOtpCode throws on failure, so this might be redundant
      ErrorHelper.BadRequestException(
        'Invalid or expired email verification code.',
      );
    }

    // Update user document
    user.email = email.toLowerCase();
    user.emailConfirm = true;
    if (user.status === UserStatus.PENDING_EMAIL_VERIFICATION) {
      user.status = UserStatus.PENDING_PROFILE_COMPLETION; // Move to next status
    }
    await user.save();

    this.logger.log(`Email ${email} verified successfully for user ${userId}.`);
    return { message: 'Email verified successfully.' };
  }

  // --- Profile Completion ---

  async completeUserProfile(
    userId: string,
    dto: CompleteProfileDto,
  ): Promise<{ token: any; user: IUser }> {
    this.logger.log(`User ${userId} completing profile.`);

    const user = await this.userRepo.findById(userId).populate('roles');
    if (!user) ErrorHelper.NotFoundException('User not found.');

    // Verify preconditions (phone and email must be verified)
    if (!user.phoneVerified || !user.emailConfirm) {
      ErrorHelper.ForbiddenException(
        'Phone and email must be verified before completing profile.',
      );
    }
    if (user.status !== UserStatus.PENDING_PROFILE_COMPLETION) {
      // Allow completion even if ACTIVE? Or only if PENDING_PROFILE_COMPLETION?
      this.logger.warn(
        `User ${userId} attempting to complete profile with status ${user.status}`,
      );
      ErrorHelper.BadRequestException(
        'Profile completion not applicable for current user status.',
      );
    }

    // Update user details
    user.firstName = dto.firstName;
    user.lastName = dto.lastName;
    user.password = await this.encryptHelper.hash(dto.password);
    user.country = dto.country;
    user.gender = dto.gender;
    user.status = UserStatus.ACTIVE; // Set status to ACTIVE

    if (dto.portalType) {
      const targetRoleName = dto.portalType as unknown as RoleNameEnum;
      this.logger.log(`Assigning role: ${targetRoleName} to user ${userId}`);

      const roleToAssign = await this.roleRepo.findOne({
        name: targetRoleName,
      });
      if (!roleToAssign) {
        this.logger.error(`Role ${targetRoleName} not found in database`);
        ErrorHelper.InternalServerErrorException(
          `Configuration Errror: Role ${targetRoleName} not found.`,
        );
      }

      const userHasRole = user.roles.some((userRoleDoc: Role) => {
        if (
          userRoleDoc &&
          userRoleDoc._id &&
          roleToAssign &&
          roleToAssign._id
        ) {
          return userRoleDoc._id.toString() === roleToAssign._id.toString();
        }
        return false;
      });

      if (!userHasRole) {
        user.roles = [roleToAssign];
        this.logger.log(
          `Role ${roleToAssign.name} assigned to user ${userId}.`,
        );
      } else {
        this.logger.log(
          `User ${userId} already has role ${roleToAssign.name}. No changes to roles needed.`,
        );
      }
    } else {
      this.logger.log(
        `No portalType provided in DTO for user ${userId}. Roles remain unchanged.`,
      );
    }

    await user.save();
    this.logger.log(
      `Profile completed for user ${userId}. Status set to ACTIVE.`,
    );

    // Generate FULL JWT session
    const fullUser = { ...user.toObject(), _id: user._id.toString() } as IUser; // Ensure ID is string
    const tokenInfo = await this.generateUserSession(fullUser); // Use existing method

    return {
      token: tokenInfo,
      user: fullUser,
    };
  }

  // async createPortalUser(
  //   payload: DriverRegistrationDto | PassengerRegistrationDto,
  //   portalType: PortalType,
  // ): Promise<any> {
  //   try {
  //     const user = await this.createUser(payload, {
  //       strategy: UserLoginStrategy.LOCAL,
  //       portalType,
  //     });

  //     const tokenInfo = await this.generateUserSession(user);

  //     return {
  //       token: tokenInfo,
  //       user: user,
  //     };
  //   } catch (error) {
  //     ErrorHelper.ConflictException('Email Already Exist');
  //     this.logger.log('createPortalUser', { error });
  //   }
  // }

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
    const { email, phoneNumber } = payload;
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

    //  let phoneVerifiedStatus = false;
    if (phoneNumber) {
      const phoneExist = await this.userRepo.findOne({
        phoneNumber: phoneNumber,
      });
      if (phoneExist?.phoneVerified) {
        ErrorHelper.ConflictException(
          'Phone number already linked to a verified account.',
        );
      }
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
      const { phoneNumber, password, portalType } = params;

      const user = await this.validateUser(phoneNumber, password, portalType);

      if (
        user.status === UserStatus.PENDING_EMAIL_VERIFICATION ||
        user.status === UserStatus.PENDING_PROFILE_COMPLETION
      ) {
        ErrorHelper.ForbiddenException(
          'Please complete your registration process before logging in.',
        );
      }

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
    phone: string,
    password: string,
    portalType?: string,
  ): Promise<IDriver | IPassenger> {
    const phoneQuery = {
      phoneNumber: phone,
    };

    const user = await this.userRepo
      .findOne(phoneQuery)
      .select('+password')
      .populate('roles', 'name');

    if (!user) {
      ErrorHelper.BadRequestException(INVALID_PHONE_NUMBER_OR_PASSWORD);
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
    console.log('roles', roleNames);

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
    const { phoneNumber, password } = params;

    const user = await this.validateUser(phoneNumber, password);

    const session = await this.userSessionService.checkSession(user._id);

    return {
      exists: !!session,
      user,
    };
  }
}
