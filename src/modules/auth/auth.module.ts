import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { EncryptHelper } from 'src/core/helpers';
import { TokenHelper } from 'src/global/utils/token.utils';
import { MailController } from '../mail/mail.controller';
import { MailEvent } from '../mail/mail.event';
import { MongooseModule } from '@nestjs/mongoose';
import { TokenSchema, Token } from '../user/schemas/token.schema';
import { MailModule } from '../mail/mail.module';
import { UserModule } from '../user/user.module';
import { roleSchema, Role } from '../user/schemas/role.schema';
import { AwsS3Module } from '../storage';
import { UserSchema, User } from '../user/schemas/user.schema';

@Module({
  imports: [
    MailModule,
    UserModule,
    MongooseModule.forFeature([
      { name: Token.name, schema: TokenSchema },
      { name: Role.name, schema: roleSchema },
      { name: User.name, schema: UserSchema },
    ]),
    AwsS3Module.forRoot('authAwsSecret'),
  ],
  providers: [
    AuthService,
    TokenHelper,
    EncryptHelper,
    MailEvent,
    MailController,
  ],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule {}
