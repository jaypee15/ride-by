import {
  Controller,
  Post,
  Body,
  UseGuards,
  Logger,
  Get,
  Query,
  Param,
  Patch,
} from '@nestjs/common';
import { RidesService } from './rides.service';
import { CreateRideDto } from './dto/create-ride.dto';
import { AuthGuard } from '../../core/guards/authenticate.guard';
import { User } from '../../core/decorators/user.decorator';
import { IUser } from '../../core/interfaces/user/user.interface';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiQuery,
} from '@nestjs/swagger';
import { Ride } from './schemas/ride.schema';
import { SearchRidesDto } from './dto/search-rides.dto';
import { PaginationResultDto } from 'src/core/dto';
import mongoose from 'mongoose';
import { ErrorHelper } from 'src/core/helpers';

@ApiTags('Rides')
@Controller('rides')
export class RidesController {
  private readonly logger = new Logger(RidesController.name);

  constructor(private readonly ridesService: RidesService) {}

  @Post()
  @UseGuards(AuthGuard) // Ensure user is logged in
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Create a new ride offer (Driver only)' })
  @ApiResponse({
    status: 201,
    description: 'Ride created successfully.',
    type: Ride,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid input data.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized - Invalid token.' })
  @ApiResponse({
    status: 403,
    description:
      'Forbidden - User is not a verified driver or vehicle/driver is invalid.',
  })
  @ApiResponse({
    status: 404,
    description: 'Not Found - Driver or Vehicle not found.',
  })
  async createRide(
    @User() driver: IUser, // Get authenticated user (should have DRIVER role)
    @Body() createRideDto: CreateRideDto,
  ): Promise<{ message: string; data: Ride }> {
    // Standard response structure
    this.logger.log(
      `Received request to create ride from driver ID: ${driver._id}`,
    );
    const newRide = await this.ridesService.createRide(
      driver._id,
      createRideDto,
    );
    return {
      message: 'Ride created successfully.',
      data: newRide.toObject() as Ride, // Return plain object
    };
  }


@Get('')
@UseGuards(AuthGuard)
@ApiOperation({ summary: 'Get all Rides (for all drivers)' })
@ApiResponse({
  status: 200,
  description: 'All rides retrieved successfully.',
})
@ApiResponse({ status: 401, description: 'Unauthorized.' })
async getAllRides(
  @User() user: IUser, // This still authenticates user
): Promise<{
  message: string;
  data: Ride[];
}> {
  const rides = await this.ridesService.getAllRides();

  return {
    message: 'All rides fetched successfully.',
    data: rides,
  };
}

  @Get('/search')
  @UseGuards(AuthGuard) // Require login to search? Or make public? Assuming logged in for now.
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Search for available rides' })
  // Add ApiQuery decorators for Swagger documentation of query parameters
  @ApiQuery({
    name: 'origin[lat]',
    type: Number,
    required: true,
    description: 'Origin latitude',
  })
  @ApiQuery({
    name: 'origin[lon]',
    type: Number,
    required: true,
    description: 'Origin longitude',
  })
  @ApiQuery({
    name: 'destination[lat]',
    type: Number,
    required: true,
    description: 'Destination latitude',
  })
  @ApiQuery({
    name: 'destination[lon]',
    type: Number,
    required: true,
    description: 'Destination longitude',
  })
  @ApiQuery({
    name: 'departureDate',
    type: String,
    required: true,
    example: '2025-08-15',
    description: 'Departure date (YYYY-MM-DD)',
  })
  @ApiQuery({
    name: 'seatsNeeded',
    type: Number,
    required: true,
    example: 1,
    description: 'Number of seats required',
  })
  @ApiQuery({
    name: 'maxDistance',
    type: Number,
    required: false,
    example: 5000,
    description: 'Max search radius in meters',
  })
  @ApiQuery({ name: 'page', type: Number, required: false, example: 1 })
  @ApiQuery({ name: 'limit', type: Number, required: false, example: 10 })
  @ApiQuery({
    name: 'order',
    enum: ['ASC', 'DESC'],
    required: false,
    example: 'DESC',
  })
  @ApiResponse({
    status: 200,
    description: 'List of matching rides found.',
    type: PaginationResultDto<Ride>,
  }) // Hint response type
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid query parameters.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  async searchRides(
    @Query() searchRidesDto: SearchRidesDto, // Use @Query to bind query params to DTO
  ): Promise<PaginationResultDto<Ride>> {
    // Return type matches service
    this.logger.log(
      `Searching rides with criteria: ${JSON.stringify(searchRidesDto)}`,
    );
    // searchRidesDto will have pagination fields inherited
    return await this.ridesService.searchRides(searchRidesDto);
    // TransformInterceptor will format the final response
  }

  // --- New Get Ride By ID Endpoint ---
  @Get(':rideId')
  @UseGuards(AuthGuard) // Or make public if needed
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get details of a specific ride' })
  @ApiResponse({ status: 200, description: 'Ride details found.', type: Ride })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid Ride ID format.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({ status: 404, description: 'Not Found - Ride not found.' })
  async getRideById(
    @Param('rideId') rideId: string,
  ): Promise<{ message: string; data: Ride }> {
    if (!mongoose.Types.ObjectId.isValid(rideId)) {
      ErrorHelper.BadRequestException('Invalid Ride ID format.');
    }
    this.logger.log(`Fetching ride details for ID: ${rideId}`);
    const ride = await this.ridesService.getRideById(rideId);
    return {
      message: 'Ride details fetched successfully.',
      data: ride.toObject() as Ride,
    };
  }

  @Patch(':rideId/start') // New endpoint
  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Start a scheduled ride (Driver only)' })
  @ApiResponse({
    status: 200,
    description: 'Ride started successfully.',
    type: Ride,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Ride cannot be started.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({ status: 403, description: 'Forbidden - Not the driver.' })
  @ApiResponse({ status: 404, description: 'Not Found - Ride not found.' })
  async startRide(
    @User() driver: IUser,
    @Param('rideId') rideId: string,
  ): Promise<{ message: string; data: Ride }> {
    if (!mongoose.Types.ObjectId.isValid(rideId)) {
      ErrorHelper.BadRequestException('Invalid Ride ID format.');
    }
    this.logger.log(`Driver ${driver._id} starting ride ${rideId}`);
    const startedRide = await this.ridesService.startRide(driver._id, rideId);
    return {
      message: 'Ride started successfully.',
      data: startedRide.toObject() as Ride,
    };
  }

  // Endpoint for GET /rides/:rideId/share-link (to be added)
  // Public endpoint GET /trip/:shareToken (to be added in a separate controller/module)
  @Get(':rideId/share-link')
  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Generate a shareable link/token for an in-progress ride',
  })
  @ApiResponse({
    status: 200,
    description: 'Share token generated successfully.',
    schema: {
      properties: {
        shareToken: { type: 'string' },
        expiresAt: { type: 'string', format: 'date-time' },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Ride not in progress.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - User not on this ride.',
  })
  @ApiResponse({ status: 404, description: 'Not Found - Ride not found.' })
  async getShareLink(
    @User() currentUser: IUser,
    @Param('rideId') rideId: string,
  ): Promise<{
    message: string;
    data: { shareToken: string; expiresAt: Date };
  }> {
    if (!mongoose.Types.ObjectId.isValid(rideId)) {
      ErrorHelper.BadRequestException('Invalid Ride ID format.');
    }
    this.logger.log(
      `User ${currentUser._id} requesting share link for ride ${rideId}`,
    );
    const result = await this.ridesService.generateShareLink(
      rideId,
      currentUser._id,
    );
    return {
      message: 'Share link generated successfully.',
      data: result,
    };
  }
}
