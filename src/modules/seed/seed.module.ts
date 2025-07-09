import { Module } from '@nestjs/common';

import { AuthModule } from '../auth/auth.module';
import { UserModule } from '../user/user.module';
import { SeedService } from './seed.service';
import { MongooseModule } from '@nestjs/mongoose';
import { Country, CountrySchema, Currency, CurrencySchema } from './schemas';
import { roleSchema, Role } from '../user/schemas/role.schema';
import { UserSchema, User } from '../user/schemas/user.schema';

@Module({
  imports: [
    AuthModule,
    UserModule,
    MongooseModule.forFeature([
      { name: Country.name, schema: CountrySchema },
      { name: User.name, schema: UserSchema },
      { name: Role.name, schema: roleSchema },
      { name: Currency.name, schema: CurrencySchema },
    ]),
  ],
  providers: [SeedService],
  exports: [SeedService],
})
export class SeedModule {}
