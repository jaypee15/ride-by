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
import { GeolocationService, PlaceSuggestion } from './geolocation.service';
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

  @Get('autocomplete')
  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Place autocomplete suggestions (Nigeria-biased)' })
  @ApiQuery({ name: 'input', type: String, required: true, example: 'Ikeja' })
  @ApiResponse({ status: 200, description: 'Suggestions returned (possibly empty).' })
  @ApiResponse({ status: 400, description: 'Input missing.' })
  async autocomplete(
    @Query('input') input?: string,
  ): Promise<PlaceSuggestion[]> {
    if (!input?.trim()) {
      throw new BadRequestException('Query parameter "input" is required.');
    }
    return this.geolocationService.autocomplete(input.trim());
  }
}
