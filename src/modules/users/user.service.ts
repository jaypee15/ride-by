import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { DateHelper, ErrorHelper } from 'src/core/helpers';
import { IPassenger, IDriver } from 'src/core/interfaces';
import { TokenHelper } from 'src/global/utils/token.utils';
import { UserSessionService } from 'src/global/user-session/service';
import { Token } from './schemas/token.schema';
import { User } from './schemas/user.schema';

@Injectable()
export class UserService {
  private logger = new Logger(UserService.name);
  constructor(
    @InjectModel(Token.name) private tokenRepo: Model<Token>,
    private tokenHelper: TokenHelper,
    private userSessionService: UserSessionService,
    @InjectModel(User.name) private userRepo: Model<User>,
  ) {}

  async generateOtpCode(
    user: IDriver | IPassenger,
    options = {
      numberOnly: true,
      length: 4,
    },
    expirationTimeInMinutes = 15,
  ): Promise<string> {
    let code = '';

    if (options.numberOnly) {
      code = this.tokenHelper.generateRandomNumber(options.length);
    } else {
      code = this.tokenHelper.generateRandomString(options.length);
    }

    this.logger.debug('Generating OTP code for user: ', user._id);
    this.logger.debug('OTP code: ', code);

    await this.tokenRepo.findOneAndDelete({ user: user?._id, isUsed: false });

    await this.tokenRepo.create({
      user: user._id,
      code,
      expirationTime: DateHelper.addToCurrent({
        minutes: expirationTimeInMinutes,
      }),
    });

    return code;
  }

  async verifyOtpCode(
    user: IDriver | IPassenger,
    code: string,
    message?: string,
  ): Promise<boolean> {
    const otp = await this.tokenRepo.findOne({
      user: user._id,
      code,
      isUsed: false,
    });

    if (!otp) {
      ErrorHelper.BadRequestException('Invalid code');
    }

    if (DateHelper.isAfter(new Date(), otp.expirationTime)) {
      ErrorHelper.BadRequestException(
        message ||
          "This code has expired. You can't change your password using this link",
      );
    }

    await otp.deleteOne();

    return true;
  }

  async logout(userId: string) {
    await this.userSessionService.delete(userId);

    return {
      success: true,
    };
  }

  async getUser(userId: string): Promise<User> {
    try {
      const user = await this.userRepo.findById(userId);
      if (!user) {
        ErrorHelper.BadRequestException('User does not exists');
      }
      return user;
    } catch (error) {
      ErrorHelper.BadRequestException(error);
    }
  }
}
