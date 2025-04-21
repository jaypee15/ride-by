import { Controller, Get, Param, Logger } from '@nestjs/common';
import { TripSharingService } from './trip-sharing.service'; // Create this service
import { ApiTags, ApiOperation, ApiResponse, ApiParam } from '@nestjs/swagger';
import { ErrorHelper } from 'src/core/helpers';

@ApiTags('Public - Trip Sharing')
@Controller('trip')
export class TripSharingController {
  private readonly logger = new Logger(TripSharingController.name);

  constructor(private readonly tripSharingService: TripSharingService) {}

  @Get(':shareToken')
  @ApiOperation({
    summary: 'Get basic public status of a shared trip using a token',
  })
  @ApiParam({
    name: 'shareToken',
    description: 'The unique token from the share link',
  })
  @ApiResponse({
    status: 200,
    description: 'Basic trip details.',
    schema: {
      /* Define limited DTO here */
    },
  })
  @ApiResponse({
    status: 404,
    description: 'Not Found - Invalid or expired share token.',
  })
  @ApiResponse({ status: 500, description: 'Internal server error.' })
  async getSharedTripStatus(
    @Param('shareToken') shareToken: string,
  ): Promise<{ message: string; data: any }> {
    this.logger.log(
      `Public request for trip status with token: ${shareToken.substring(0, 8)}...`,
    );
    const tripData =
      await this.tripSharingService.getTripStatusByToken(shareToken);
    if (!tripData) {
      ErrorHelper.NotFoundException('Invalid or expired share link.');
    }
    return {
      message: 'Trip status retrieved successfully.',
      data: tripData, // Service should return limited data
    };
  }
}
