import { Module } from '@nestjs/common';
import { MailController } from './mail.controller';
import { MailService } from './mail.service';
import { SecretsModule } from 'src/global/secrets/module';
import { SecretsService } from 'src/global/secrets/service';
import { BullModule } from '@nestjs/bull';
import { MongooseModule } from '@nestjs/mongoose';
import { Email, EmailSchema } from './schema/email.schema';
import { UserModule } from '../user/user.module';
import { MailEvent } from './mail.event';
import { EmailProcessor } from './cron-job/email.processor';
import { TokenSchema, Token } from '../user/schemas/token.schema';
import { UserSchema, User } from '../user/schemas/user.schema';
import { roleSchema, Role } from '../user/schemas/role.schema';
import { ResendService } from './resend.service';

@Module({
  imports: [
    SecretsModule,
    UserModule,
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
      name: 'emailQueue',
    }),
    MongooseModule.forFeature([
      {
        name: Email.name,
        schema: EmailSchema,
      },
      { name: Token.name, schema: TokenSchema },
      { name: User.name, schema: UserSchema },
      { name: Role.name, schema: roleSchema },
    ]),
  ],
  controllers: [MailController],
  providers: [
    MailService,
    MailEvent,
    MailController,
    EmailProcessor,
    ResendService,
  ],
  exports: [MailService, MailEvent, BullModule, MailController],
})
export class MailModule {}
