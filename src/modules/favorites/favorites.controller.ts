import { Controller, Get, Post, Delete, Body, Param, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import mongoose from 'mongoose';
import { FavoritesService } from './favorites.service';
import { AddFavoriteDriverDto } from './dto/add-favorite-driver.dto';
import { AuthGuard } from '../../core/guards/authenticate.guard';
import { User } from '../../core/decorators/user.decorator';
import { IUser } from '../../core/interfaces/user/user.interface';
import { ErrorHelper } from 'src/core/helpers';

@ApiTags('FavoriteDrivers')
@Controller()
export class FavoritesController {
  constructor(private readonly favoritesService: FavoritesService) {}

  @Get('/passenger/favorite-drivers')
  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'List my favorite drivers' })
  async listMine(@User() passenger: IUser) {
    const data = await this.favoritesService.listMine(passenger._id);
    return { message: 'Favorite drivers fetched successfully.', data };
  }

  @Post('/passenger/favorite-drivers')
  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Favorite a driver (idempotent)' })
  async add(@User() passenger: IUser, @Body() dto: AddFavoriteDriverDto) {
    if (!mongoose.Types.ObjectId.isValid(dto.driverId)) {
      ErrorHelper.BadRequestException('Invalid driver ID format.');
    }
    const data = await this.favoritesService.add(passenger._id, dto.driverId);
    return { message: 'Driver favorited successfully.', data };
  }

  @Delete('/passenger/favorite-drivers/:driverId')
  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Unfavorite a driver' })
  async remove(@User() passenger: IUser, @Param('driverId') driverId: string) {
    if (!mongoose.Types.ObjectId.isValid(driverId)) {
      ErrorHelper.BadRequestException('Invalid driver ID format.');
    }
    const data = await this.favoritesService.remove(passenger._id, driverId);
    return { message: 'Driver unfavorited successfully.', data };
  }
}
