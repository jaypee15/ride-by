import { Module, Global } from '@nestjs/common';
import { NotificationService } from './notification.service';
import { SecretsModule } from 'src/global/secrets/module'; // Ensure secrets are available
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from '../user/schemas/user.schema';

@Global() // Make service available globally without importing module explicitly
@Module({
  imports: [
    SecretsModule,
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
  ],
  providers: [NotificationService],
  exports: [NotificationService],
})
export class NotificationModule {}
