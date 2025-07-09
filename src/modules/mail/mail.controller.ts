import { Controller, Logger, Post } from '@nestjs/common';
import { SendMailDto } from './dto/mail.dto';
import { MailService } from './mail.service';
import { MailType } from './enums';

@Controller()
export class MailController {
  private logger = new Logger(MailController.name);

  constructor(private readonly mailService: MailService) {}

  @Post('mail')
  async sendMail(data: SendMailDto) {
    this.logger.log('sendMail event received', JSON.stringify(data));

    try {
      switch (data.type) {
        case MailType.USER_CONFIRMATION:
          await this.mailService.sendUserConfirmation(data);
          this.logger.log('sendUserConfirmation called');
          break;

        case MailType.USER_CREDENTIALS:
          await this.mailService.sendUserCredentials(data);
          this.logger.log('sendUserCredentials called');
          break;

        case MailType.RESET_PASSWORD:
          await this.mailService.sendResetPassword(data);
          this.logger.log('sendResetPassword called');
          break;

        case MailType.IN_APP_EMAIL:
          await this.mailService.sendInAppEmailNotification(data);
          this.logger.log('sendInAppEmailNotification called');
          break;

        default:
          break;
      }
    } catch (error) {
      this.logger.error(error);
    }
  }
}
