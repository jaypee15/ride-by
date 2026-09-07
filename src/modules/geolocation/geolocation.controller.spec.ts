import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, HttpException } from '@nestjs/common';
import { GeolocationController } from './geolocation.controller';
import { GeolocationService } from './geolocation.service';
import { AuthGuard } from '../../core/guards/authenticate.guard';

describe('GeolocationController', () => {
  let controller: GeolocationController;
  const mockService = { geocode: jest.fn(), autocomplete: jest.fn() };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [GeolocationController],
      providers: [{ provide: GeolocationService, useValue: mockService }],
    })
      .overrideGuard(AuthGuard)
      .useValue({ canActivate: () => true })
      .compile();
    controller = module.get<GeolocationController>(GeolocationController);
    jest.clearAllMocks();
  });

  it('returns coords for a known address', async () => {
    mockService.geocode.mockResolvedValue({ lat: 6.5244, lng: 3.3792 });
    await expect(controller.geocode('Ikeja, Lagos')).resolves.toEqual({
      lat: 6.5244,
      lng: 3.3792,
    });
    expect(mockService.geocode).toHaveBeenCalledWith('Ikeja, Lagos');
  });

  it('throws 400 when address is missing', async () => {
    await expect(controller.geocode('')).rejects.toBeInstanceOf(BadRequestException);
    await expect(controller.geocode(undefined)).rejects.toBeInstanceOf(BadRequestException);
  });

  it('throws 400 when the service resolves null', async () => {
    mockService.geocode.mockResolvedValue(null);
    await expect(controller.geocode('Nowhere XX')).rejects.toBeInstanceOf(BadRequestException);
  });
});

describe('GeolocationController.autocomplete', () => {
  let controller: GeolocationController;
  const mockService = { autocomplete: jest.fn() };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [GeolocationController],
      providers: [{ provide: GeolocationService, useValue: mockService }],
    })
      .overrideGuard(AuthGuard)
      .useValue({ canActivate: () => true })
      .compile();
    controller = module.get<GeolocationController>(GeolocationController);
    jest.clearAllMocks();
  });

  it('returns the service suggestions verbatim', async () => {
    mockService.autocomplete.mockResolvedValue([{ description: 'Ikeja, Lagos', placeId: 'ChIJ1' }]);
    await expect(controller.autocomplete('Ike')).resolves.toEqual([
      { description: 'Ikeja, Lagos', placeId: 'ChIJ1' },
    ]);
    expect(mockService.autocomplete).toHaveBeenCalledWith('Ike');
  });

  it('throws 400 when input is missing', async () => {
    const err = await controller.autocomplete('').catch((e) => e);
    expect(err).toBeInstanceOf(HttpException);
    expect((err as HttpException).getStatus()).toBe(400);
  });
});
