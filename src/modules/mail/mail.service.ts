import { Injectable, Logger } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import * as ejs from 'ejs';
import * as fs from 'fs';
import { SendMailDto } from './dto/mail.dto';
import { Email } from './schema/email.schema';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';

@Injectable()
export class MailService {
  private logger = new Logger(MailService.name);
  private from = '"TravEazi Team" <notifications@TravEazi.com>';

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
    private mailerService: MailerService,
  ) {}

  async sendUserConfirmation(data: SendMailDto) {
    const renderedEmail = ejs.render(this.confirmationTemplate, {
      name: data.data['firstName'],
      email: data.data['email'],
      code: data.data['code'],
    });

    return this.mailerService.sendMail({
      to: data.to,
      from: this.from,
      subject: data.subject,
      template: './confirmation',
      context: {
        name: data.data['firstName'],
        email: data.data['email'],
        code: data.data['code'],
      },
      headers: {
        'X-Category': data.type,
      },
      html: renderedEmail,
      text: renderedEmail,
    });
  }

  async sendResetPassword(data: SendMailDto) {
    const renderedEmail = ejs.render(this.resetpasswordTemplate, {
      name: data.data['firstName'],
      url: data.data['url'],
    });

    return this.mailerService.sendMail({
      to: data.to,
      from: this.from,
      subject: data.subject,
      template: './resetpassword',
      html: renderedEmail,
      text: renderedEmail,
      context: {
        name: data.data['firstName'],
        url: data.data['url'],
      },
      headers: {
        'X-Category': data.type,
      },
    });
  }

  async sendUserCredentials(data: SendMailDto) {
    const renderedEmail = ejs.render(this.credentialsTemplate, {
      name: data.data['firstName'],
      email: data.data['email'],
      password: data.data['password'],
    });

    return this.mailerService.sendMail({
      to: data.to,
      from: this.from,
      subject: data.subject,
      template: './credentials',
      context: {
        name: data.data['firstName'],
        email: data.data['email'],
        password: data.data['password'],
      },
      headers: {
        'X-Category': data.type,
      },
      html: renderedEmail,
      text: renderedEmail,
    });
  }

  async sendInAppEmailNotification(data: SendMailDto) {
    const renderedEmail = ejs.render(this.inAppEmaillTemplate, {
      name: data.data['firstName'],
      email: data.data['email'],
      body: data.data['body'],
    });

    return this.mailerService.sendMail({
      to: data.to,
      from: this.from,
      subject: data.subject,
      template: './emailnotification',
      context: {
        name: data.data['firstName'],
        email: data.data['email'],
        body: data.data['body'],
      },
      headers: {
        'X-Category': data.type,
      },
      html: renderedEmail,
      text: renderedEmail,
    });
  }
}
