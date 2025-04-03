import { Module } from '@nestjs/common';
import { MailerModule } from '@nestjs-modules/mailer';
import { EjsAdapter } from '@nestjs-modules/mailer/dist/adapters/ejs.adapter';
import { join } from 'path';
import { MailController } from './mail.controller';
import { MailService } from './mail.service';
import { SecretsModule } from 'src/global/secrets/module';
import { SecretsService } from 'src/global/secrets/service';
import { BullModule } from '@nestjs/bull';
import { MongooseModule } from '@nestjs/mongoose';
import { Email, EmailSchema } from './schema/email.schema';
import { UserModule } from '../user/user.module';
import { MailEvent } from './mail.event';
import { Token, TokenSchema } from '../user/schemas/token.entity';
import { UserSchema, User } from '../auth/entities/schemas';
import { Role, roleSchema } from '../admin/entities/role.entity';
import { Rider, RiderSchema } from '../rider/entities/rider.entity';
import { Rides, Rideschema } from '../rider/entities/rides.entity';
import { EmailProcessor } from './cron-job/email.processor';

@Module({
  imports: [
    SecretsModule,
    UserModule,
    MailerModule.forRootAsync({
      useFactory: ({ mailSecret }: SecretsService) => ({
        transport: {
          host: mailSecret.MAIL_HOST,
          port: mailSecret.MAIL_PORT,
          auth: {
            user: mailSecret.MAIL_USERNAME,
            pass: mailSecret.MAIL_PASSWORD,
          },
        },
        pool: true, // Enable connection pooling
        maxConnections: 5, // Limit number of connections
        maxMessages: 100, // Limit number of messages per connection
        tls: {
          rejectUnauthorized: false,
        },
        defaults: {
          from: '"No Reply" <no-reply@TravEazi.com>',
        },
        preview: true,
        template: {
          dir: join(__dirname, 'templates'),
          adapter: new EjsAdapter(),
          options: {
            strict: false,
          },
        },
      }),
      inject: [SecretsService],
      imports: [SecretsModule],
    }),
    // Register Bull queue for email processing
    BullModule.forRootAsync({
      useFactory: ({ userSessionRedis }: SecretsService) => ({
        redis: {
          host: userSessionRedis.REDIS_HOST,
          port: userSessionRedis.REDIS_PORT,
          password: userSessionRedis.REDIS_PASSWORD,
        },
      }),
      inject: [SecretsService],
      imports: [SecretsModule],
    }),

    BullModule.registerQueue({
      name: 'emailQueue', // Name of the queue for email jobs
    }),
    MongooseModule.forFeature([
      {
        name: Email.name,
        schema: EmailSchema,
      },
      { name: Token.name, schema: TokenSchema },
      { name: User.name, schema: UserSchema },
      { name: Role.name, schema: roleSchema },
      { name: Rider.name, schema: RiderSchema },
      { name: Rides.name, schema: Rideschema },
    ]),
  ],
  controllers: [MailController],
  providers: [MailService, MailEvent, MailController, EmailProcessor],
  exports: [MailService, MailEvent, BullModule, MailController],
})
export class MailModule {}
