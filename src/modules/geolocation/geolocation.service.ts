import {
  Injectable,
  Logger,
  InternalServerErrorException,
  BadRequestException,
} from '@nestjs/common';
// Keep enum imports for other parts like TravelMode
import {
  Client,
  DirectionsRequest,
  GeocodeRequest,
  ReverseGeocodeRequest,
  LatLngLiteral,
  TravelMode,
} from '@googlemaps/google-maps-services-js';
import { SecretsService } from '../../global/secrets/service';
import { ErrorHelper } from 'src/core/helpers';

// Interfaces remain the same
export interface Coordinates {
  lat: number;
  lng: number;
}
export interface AddressComponents {
  streetNumber?: string;
  route?: string;
  locality?: string;
  administrativeAreaLevel1?: string;
  country?: string;
  postalCode?: string;
  formattedAddress?: string;
}
export interface RouteInfo {
  distanceMeters: number;
  durationSeconds: number;
}

@Injectable()
export class GeolocationService {
  private readonly logger = new Logger(GeolocationService.name);
  private googleMapsClient: Client | null = null;

  constructor(private secretsService: SecretsService) {
    const { apiKey } = this.secretsService.googleMaps;
    if (apiKey) {
      this.googleMapsClient = new Client({});
    } else {
      this.logger.error(
        'Google Maps API Key not found. GeolocationService will not function.',
      );
    }
  }

  private checkClient(): void {
    if (!this.googleMapsClient) {
      this.logger.error(
        'Google Maps client not initialized due to missing API key.',
      );
      throw new InternalServerErrorException(
        'Geolocation service is not configured properly.',
      );
    }
  }

  async geocode(address: string): Promise<Coordinates | null> {
    this.checkClient();
    const params: GeocodeRequest['params'] = {
      address: address,
      key: this.secretsService.googleMaps.apiKey,
      components: 'country:NG',
    };

    try {
      this.logger.log(`Geocoding address: ${address}`);
      const response = await this.googleMapsClient.geocode({ params });

      if (response.data.status === 'OK' && response.data.results.length > 0) {
        const location = response.data.results[0].geometry.location;
        this.logger.log(
          `Geocode successful for "${address}": ${JSON.stringify(location)}`,
        );
        return location;
      } else {
        this.logger.warn(
          `Geocoding failed for address "${address}". Status: ${response.data.status}, Error: ${response.data.error_message}`,
        );
        if (response.data.status === 'ZERO_RESULTS') {
          throw new BadRequestException(
            `Could not find coordinates for the address: ${address}`,
          );
        }
        throw new InternalServerErrorException(
          `Geocoding failed with status: ${response.data.status}`,
        );
      }
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof InternalServerErrorException
      ) {
        throw error;
      }
      this.logger.error(
        `Error calling Google Geocoding API for address "${address}": ${error.message}`,
        error.stack,
      );
      ErrorHelper.InternalServerErrorException('Failed to perform geocoding.');
    }
  }

  async reverseGeocode(
    lat: number,
    lng: number,
  ): Promise<AddressComponents | null> {
    this.checkClient();
    const params: ReverseGeocodeRequest['params'] = {
      latlng: { lat, lng },
      key: this.secretsService.googleMaps.apiKey,
    };

    try {
      this.logger.log(`Reverse geocoding coordinates: lat=${lat}, lng=${lng}`);
      const response = await this.googleMapsClient.reverseGeocode({ params });

      if (response.data.status === 'OK' && response.data.results.length > 0) {
        const firstResult = response.data.results[0];
        const components: AddressComponents = {
          formattedAddress: firstResult.formatted_address,
        };

        // Cast component.types to string[] before using .includes with string literals
        firstResult.address_components.forEach((component) => {
          const types = component.types as string[]; // Cast here
          if (types.includes('street_number'))
            components.streetNumber = component.long_name;
          if (types.includes('route')) components.route = component.long_name;
          if (types.includes('locality'))
            components.locality = component.long_name;
          if (types.includes('administrative_area_level_1'))
            components.administrativeAreaLevel1 = component.long_name;
          if (types.includes('country'))
            components.country = component.long_name;
          if (types.includes('postal_code'))
            components.postalCode = component.long_name;
        });

        this.logger.log(
          `Reverse geocode successful for ${lat},${lng}: "${components.formattedAddress}"`,
        );
        return components;
      } else {
        this.logger.warn(
          `Reverse geocoding failed for ${lat},${lng}. Status: ${response.data.status}, Error: ${response.data.error_message}`,
        );
        return null;
      }
    } catch (error) {
      this.logger.error(
        `Error calling Google Reverse Geocoding API for ${lat},${lng}: ${error.message}`,
        error.stack,
      );
      ErrorHelper.InternalServerErrorException(
        'Failed to perform reverse geocoding.',
      );
    }
    return null;
  }

  async calculateRoute(
    origin: LatLngLiteral,
    destination: LatLngLiteral,
    waypoints?: LatLngLiteral[],
  ): Promise<RouteInfo | null> {
    this.checkClient();
    const params: DirectionsRequest['params'] = {
      origin: origin,
      destination: destination,
      waypoints: waypoints,
      key: this.secretsService.googleMaps.apiKey,
      mode: TravelMode.driving, // Enum is correct here
    };

    try {
      this.logger.log(
        `Calculating route from ${JSON.stringify(origin)} to ${JSON.stringify(destination)}`,
      );
      const response = await this.googleMapsClient.directions({ params });

      if (response.data.status === 'OK' && response.data.routes.length > 0) {
        const route = response.data.routes[0];
        if (route.legs.length > 0) {
          let totalDistance = 0;
          let totalDuration = 0;
          route.legs.forEach((leg) => {
            totalDistance += leg.distance?.value || 0;
            totalDuration += leg.duration?.value || 0;
          });

          this.logger.log(
            `Route calculation successful: Distance=${totalDistance}m, Duration=${totalDuration}s`,
          );
          return {
            distanceMeters: totalDistance,
            durationSeconds: totalDuration,
          };
        }
      }

      this.logger.warn(
        `Route calculation failed. Status: ${response.data.status}, Error: ${response.data.error_message}`,
      );
      if (response.data.status === 'ZERO_RESULTS') {
        throw new BadRequestException(
          'Could not find a driving route between the specified locations.',
        );
      }
      return null;
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      this.logger.error(
        `Error calling Google Directions API: ${error.message}`,
        error.stack,
      );
      ErrorHelper.InternalServerErrorException('Failed to calculate route.');
    }
    return null;
  }
}
