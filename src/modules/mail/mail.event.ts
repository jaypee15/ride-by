import { Injectable, Logger } from '@nestjs/common';
import { SecretsService } from 'src/global/secrets/service';
import { MailType } from './enums';
import { MailController } from './mail.controller';
import { Queue } from 'bull';
import { InjectQueue } from '@nestjs/bull';
import { UserService } from '../user/user.service';

@Injectable()
export class MailEvent {
  private logger = new Logger(MailEvent.name);
  constructor(
    @InjectQueue('emailQueue') private emailQueue: Queue,
    private secretService: SecretsService,
    private mailController: MailController,
    private userService: UserService,
  ) {}

  async sendUserConfirmation(user, code: string) {
    const sendMailDto = {
      to: [user.email],
      subject: 'Welcome to TravEazi! Confirm your Email',
      type: MailType.USER_CONFIRMATION,
      data: {
        firstName: user.firstName || 'User',
        email: user.email,
        code,
      },
      saveAsNotification: false,
    };

    await this.mailController.sendMail(sendMailDto);
  }

  async sendResetPassword(user, token: string, callbackURL?: string) {
    const url = new URL(callbackURL);
    url.searchParams.append('code', token);
    this.logger.log('url', url);

    const sendMailDto = {
      to: [user.email],
      subject: 'Reset Password - TraveEazi',
      type: MailType.RESET_PASSWORD,
      data: {
        firstName: user.firstName || 'User',
        url,
      },
      saveAsNotification: false,
    };

    await this.mailController.sendMail(sendMailDto);
  }

  async sendUserCredentials(user, password: string) {
    const sendMailDto = {
      to: [user.email],
      subject: 'Welcome to TravEazi! Here are your login credentials',
      type: MailType.USER_CREDENTIALS,
      data: {
        firstName: user.firstName || 'User',
        email: user.email,
        password,
      },
      saveAsNotification: false,
    };

    await this.mailController.sendMail(sendMailDto);
  }
}
