import { Module } from '@nestjs/common';
import { TwilioService } from './twilio.service';
import { SecretsModule } from '../../global/secrets/module';

@Module({
  imports: [SecretsModule],
  providers: [TwilioService],
  exports: [TwilioService],
})
export class TwilioModule {}
