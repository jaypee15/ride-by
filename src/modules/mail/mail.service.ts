import { Injectable, Logger } from '@nestjs/common';
import * as ejs from 'ejs';
import * as fs from 'fs';
import { SendMailDto } from './dto/mail.dto';
import { Email } from './schema/email.schema';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { ResendService } from './resend.service';

@Injectable()
export class MailService {
  private logger = new Logger(MailService.name);
  private from = '"TravEazi Team" <hello@demomailtrap.com>';

  private confirmationTemplate = fs.readFileSync(
    __dirname + '/templates/confirmation.ejs',
    { encoding: 'utf-8' },
  );

  private resetpasswordTemplate = fs.readFileSync(
    __dirname + '/templates/resetpassword.ejs',
    { encoding: 'utf-8' },
  );
  private credentialsTemplate = fs.readFileSync(
    __dirname + '/templates/credentials.ejs',
    { encoding: 'utf-8' },
  );

  private inAppEmaillTemplate = fs.readFileSync(
    __dirname + '/templates/marketing.ejs',
    { encoding: 'utf-8' },
  );

  constructor(
    @InjectModel(Email.name)
    private emailRepo: Model<Email>,
    private resendService: ResendService,
  ) {}

  async sendUserConfirmation(data: SendMailDto) {
    const renderedEmail = ejs.render(this.confirmationTemplate, {
      name: data.data['firstName'],
      email: data.data['email'],
      code: data.data['code'],
    });

    await this.resendService.sendEmail({
      to: data.to,
      subject: data.subject,
      html: renderedEmail,
      text: renderedEmail,
      headers: { 'X-Category': data.type },
    });
  }

  async sendResetPassword(data: SendMailDto) {
    const renderedEmail = ejs.render(this.resetpasswordTemplate, {
      name: data.data['firstName'],
      code: data.data['code'],
    });

    await this.resendService.sendEmail({
      to: data.to,
      subject: data.subject,
      html: renderedEmail,
      text: renderedEmail,
      headers: { 'X-Category': data.type },
    });
  }

  async sendUserCredentials(data: SendMailDto) {
    const renderedEmail = ejs.render(this.credentialsTemplate, {
      name: data.data['firstName'],
      email: data.data['email'],
      password: data.data['password'],
    });

    await this.resendService.sendEmail({
      to: data.to,
      subject: data.subject,
      html: renderedEmail,
      text: renderedEmail,
      headers: { 'X-Category': data.type },
    });
  }

  async sendInAppEmailNotification(data: SendMailDto) {
    const renderedEmail = ejs.render(this.inAppEmaillTemplate, {
      name: data.data['firstName'],
      email: data.data['email'],
      body: data.data['body'],
    });

    await this.resendService.sendEmail({
      to: data.to,
      subject: data.subject,
      html: renderedEmail,
      text: renderedEmail,
      headers: { 'X-Category': data.type },
    });
  }
}
