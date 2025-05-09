import { Injectable, Logger, OnApplicationBootstrap } from '@nestjs/common';

import { Country, Currency } from './schemas';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { countriesSeed } from './countries/countries';
import { admins, roleSeed } from './data';
import { UserLoginStrategy } from 'src/core/interfaces';
import { AuthService } from '../auth/auth.service';
import { PortalType } from 'src/core/enums/auth.enum';
import { Role } from '../user/schemas/role.schema';
import { currencies } from './currencies/currencies';

@Injectable()
export class SeedService implements OnApplicationBootstrap {
  private logger = new Logger(SeedService.name);

  constructor(
    @InjectModel(Country.name)
    private countryRepo: Model<Country>,
    @InjectModel(Role.name)
    private roleRepo: Model<Role>,
    @InjectModel(Currency.name)
    private currencyRepo: Model<Currency>,
    private authService: AuthService,
  ) {}

  async onApplicationBootstrap() {
    this.logger.log('Seeding...');
    await this.seedCountries();
    await this.seedRoles();
    await this.createAdmins();
    await this.seedCurrencies();
    this.logger.log('Seeding completed');
  }

  async seedCountries() {
    const countryCount = await this.countryRepo.countDocuments({});

    if (countryCount > 0) {
      this.logger.log('Seeding country actions skipped');
      return;
    }

    this.logger.log('Seeding countries...');
    await this.countryRepo.insertMany(countriesSeed);
    this.logger.log('Seeding countries done');
  }

  async createAdmins() {
    this.logger.log('Seeding traveazi admins...!!!');
    const password = 'Traveazi123$';

    await Promise.allSettled(
      admins.map(async ({ data }) => {
        await this.authService.createUser(
          {
            email: data.email.toLowerCase(),
            password,
            firstName: data.firstName,
            lastName: data.lastName,
            termsAccepted: true,
          },
          {
            strategy: UserLoginStrategy.LOCAL,
            portalType: PortalType.ADMIN,
            adminCreated: true,
          },
        );
      }),
    );
    this.logger.log('Seeding admins completed');
  }

  async seedRoles() {
    this.logger.log('Seeding role actions...');
    for (const role of roleSeed) {
      try {
        const roleInstance = await this.roleRepo.findOne({
          name: role.name,
        });

        if (!roleInstance) {
          this.logger.log(`Creating role ${role.name}`);
          await this.roleRepo.create(role);
          continue;
        }

        await this.roleRepo.updateOne(
          { _id: roleInstance._id },
          { actions: role.actions },
        );
      } catch (err) {
        this.logger.error(err);
      }
    }

    this.logger.log('Seeding role actions completed');
  }

  async seedCurrencies() {
    const currencyCount = await this.currencyRepo.countDocuments({});
    this.logger.log(`currency count is ${currencyCount}`);
    if (currencyCount > 0) return;

    await this.currencyRepo.insertMany(currencies, { lean: true });

    this.logger.log('Seeding Currencies completed');
  }
}
