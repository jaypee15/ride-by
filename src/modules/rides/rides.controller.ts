import {
  Controller,
  Post,
  Body,
  UseGuards,
  Logger,
  Get,
  Query,
  Param,
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
}
