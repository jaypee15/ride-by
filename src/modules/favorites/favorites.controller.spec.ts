import { Test, TestingModule } from '@nestjs/testing';
import { HttpException } from '@nestjs/common';
import { FavoritesController } from './favorites.controller';
import { FavoritesService } from './favorites.service';
import { AuthGuard } from '../../core/guards/authenticate.guard';

describe('FavoritesController', () => {
  let controller: FavoritesController;
  const mockService = { listMine: jest.fn(), add: jest.fn(), remove: jest.fn() };
  const passengerId = '507f1f77bcf86cd799439011';
  const driverId = '507f1f77bcf86cd799439012';
  const passenger = { _id: passengerId } as any;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [FavoritesController],
      providers: [{ provide: FavoritesService, useValue: mockService }],
    })
      .overrideGuard(AuthGuard)
      .useValue({ canActivate: () => true })
      .compile();
    controller = module.get<FavoritesController>(FavoritesController);
    jest.clearAllMocks();
  });

  it('lists my favorites', async () => {
    mockService.listMine.mockResolvedValue([{ _id: 'f1' }]);
    await expect(controller.listMine(passenger)).resolves.toEqual({
      message: 'Favorite drivers fetched successfully.',
      data: [{ _id: 'f1' }],
    });
    expect(mockService.listMine).toHaveBeenCalledWith(passengerId);
  });

  it('adds a favorite', async () => {
    mockService.add.mockResolvedValue({ _id: 'f2' });
    await expect(controller.add(passenger, { driverId })).resolves.toEqual({
      message: 'Driver favorited successfully.',
      data: { _id: 'f2' },
    });
    expect(mockService.add).toHaveBeenCalledWith(passengerId, driverId);
  });

  it('rejects an invalid driver id', async () => {
    const err = await controller.add(passenger, { driverId: 'nope' }).catch((e) => e);
    expect(err).toBeInstanceOf(HttpException);
    expect((err as HttpException).getStatus()).toBe(400);
  });

  it('removes a favorite', async () => {
    mockService.remove.mockResolvedValue({ deleted: true });
    await expect(controller.remove(passenger, driverId)).resolves.toEqual({
      message: 'Driver unfavorited successfully.',
      data: { deleted: true },
    });
    expect(mockService.remove).toHaveBeenCalledWith(passengerId, driverId);
  });
});
