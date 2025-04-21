import { Module } from '@nestjs/common';
import { GeolocationService } from './geolocation.service';
import { SecretsModule } from 'src/global/secrets/module';

@Module({
  imports: [SecretsModule],
  providers: [GeolocationService],
  exports: [GeolocationService],
})
export class GeolocationModule {}
