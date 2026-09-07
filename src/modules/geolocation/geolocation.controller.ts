import {
  Controller,
  Get,
  Query,
  UseGuards,
  BadRequestException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiQuery,
} from '@nestjs/swagger';
import { GeolocationService } from './geolocation.service';
import { AuthGuard } from '../../core/guards/authenticate.guard';

@ApiTags('Geolocation')
@Controller('geolocation')
export class GeolocationController {
  constructor(private readonly geolocationService: GeolocationService) {}

  @Get('geocode')
  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Geocode an address to coordinates (Nigeria-biased)' })
  @ApiQuery({ name: 'address', type: String, required: true, example: 'Ikeja, Lagos' })
  @ApiResponse({ status: 200, description: 'Coordinates resolved.' })
  @ApiResponse({ status: 400, description: 'Address missing or not found.' })
  async geocode(
    @Query('address') address?: string,
  ): Promise<{ lat: number; lng: number }> {
    if (!address?.trim()) {
      throw new BadRequestException('Query parameter "address" is required.');
    }
    const coords = await this.geolocationService.geocode(address.trim());
    if (!coords) {
      throw new BadRequestException(
        `Could not find coordinates for the address: ${address.trim()}`,
      );
    }
    return coords;
  }
}
