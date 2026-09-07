import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { FavoriteDriver, FavoriteDriverDocument } from './schemas/favorite-driver.schema';
import { User, UserDocument } from '../user/schemas/user.schema';

@Injectable()
export class FavoritesService {
  constructor(
    @InjectModel(FavoriteDriver.name) private readonly favModel: Model<FavoriteDriverDocument>,
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
  ) {}

  async listMine(passengerId: string) {
    return this.favModel
      .find({ passenger: passengerId })
      .populate('driver', 'firstName lastName avatar')
      .sort({ createdAt: -1 })
      .lean();
  }

  async add(passengerId: string, driverId: string) {
    if (passengerId === driverId) {
      throw new BadRequestException('You cannot favorite yourself.');
    }
    const driver = await this.userModel.findById(driverId).select('_id').lean();
    if (!driver) {
      throw new NotFoundException('Driver not found.');
    }
    const existing = await this.favModel.findOne({ passenger: passengerId, driver: driverId }).lean();
    if (existing) return existing;
    return this.favModel.create({ passenger: passengerId, driver: driverId });
  }

  async remove(passengerId: string, driverId: string) {
    const res = await this.favModel.deleteOne({ passenger: passengerId, driver: driverId });
    if (res.deletedCount === 0) {
      throw new NotFoundException('Favorite not found.');
    }
    return { deleted: true };
  }
}
