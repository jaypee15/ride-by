import {
  Controller,
  Post,
  Body,
  UseGuards,
  Logger,
  Param,
  UploadedFile,
  UseInterceptors,
  ParseEnumPipe,
  Get,
} from '@nestjs/common';
import { DriverService } from './driver.service';
import { RegisterVehicleDto } from './dto/register-vehicle.dto';
import { AuthGuard } from '../../core/guards/authenticate.guard';
import { User } from '../../core/decorators/user.decorator';
import { IUser } from '../../core/interfaces/user/user.interface';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiConsumes,
  ApiBody,
} from '@nestjs/swagger';
import { Vehicle } from './schemas/vehicle.schema'; // Import for response type
import { VehicleDocumentType } from './enums/vehicle-document-type.enum';
import { ErrorHelper } from 'src/core/helpers';

@ApiTags('Driver')
@ApiBearerAuth() // Requires JWT token
@UseGuards(AuthGuard) // Protect all routes in this controller
@Controller('driver') // Base path for vehicle-related driver actions
export class DriverController {
  private readonly logger = new Logger(DriverController.name);

  constructor(private readonly driverService: DriverService) {}

  @Post('vehicles/register')
  @ApiOperation({ summary: 'Register a new vehicle for the logged-in driver' })
  @ApiResponse({
    status: 201,
    description: 'Vehicle registered successfully.',
    type: Vehicle,
  }) // Use the schema class for response type hint
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid input data.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized - Invalid token.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - User is not a driver.',
  })
  @ApiResponse({
    status: 409,
    description: 'Conflict - Plate number already exists.',
  })
  async registerVehicle(
    @User() driver: IUser, // Get authenticated user from decorator
    @Body() registerVehicleDto: RegisterVehicleDto,
  ): Promise<{ message: string; data: Vehicle }> {
    // Adjust return type for standard response
    this.logger.log(
      `Received request to register vehicle from driver ID: ${driver._id}`,
    );
    const newVehicle = await this.driverService.registerVehicle(
      driver._id,
      registerVehicleDto,
    );
    return {
      message: 'Vehicle registered successfully.',
      data: newVehicle.toObject() as Vehicle, // Convert Mongoose doc to plain object
    };
  }

  @Post(':vehicleId/documents')
  @UseInterceptors(FileInterceptor('documentFile')) // 'documentFile' is the field name in the form-data
  @ApiOperation({ summary: 'Upload a document for a specific vehicle' })
  @ApiConsumes('multipart/form-data') // Specify content type for file upload
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        documentFile: {
          // Must match FileInterceptor field name
          type: 'string',
          format: 'binary',
          description:
            'The vehicle document file (e.g., registration, insurance).',
        },
        documentType: {
          type: 'string',
          enum: Object.values(VehicleDocumentType), // Use enum values for Swagger
          description: 'The type of document being uploaded.',
        },
        // Optionally add other fields like insuranceExpiryDate here if needed
      },
      required: ['documentFile', 'documentType'], // Mark required fields
    },
  })
  @ApiResponse({
    status: 201,
    description: 'Document uploaded successfully.',
    type: Vehicle,
  })
  @ApiResponse({
    status: 400,
    description:
      'Bad Request - Missing file, invalid type, or invalid vehicle ID.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Driver does not own vehicle.',
  })
  @ApiResponse({ status: 404, description: 'Not Found - Vehicle not found.' })
  async uploadVehicleDocument(
    @User() driver: IUser,
    @Param('vehicleId') vehicleId: string, // Use @Param for path parameters
    @UploadedFile() file: Express.Multer.File, // Get the uploaded file
    @Body(
      'documentType',
      new ParseEnumPipe(VehicleDocumentType, {
        // Validate documentType against enum
        exceptionFactory: () =>
          ErrorHelper.BadRequestException('Invalid document type specified.'),
      }),
    )
    documentType: VehicleDocumentType,
  ): Promise<{ message: string; data: Vehicle }> {
    if (!file) {
      ErrorHelper.BadRequestException('Document file is required.');
    }
    this.logger.log(
      `Received request to upload ${documentType} for vehicle ${vehicleId} from driver ${driver._id}`,
    );
    const updatedVehicle = await this.driverService.uploadVehicleDocument(
      driver._id,
      vehicleId,
      file,
      documentType,
    );
    return {
      message: `${documentType} uploaded successfully.`,
      data: updatedVehicle.toObject() as Vehicle,
    };
  }

  @Get('profile-status')
  @ApiOperation({
    summary: "Get the logged-in driver's profile and verification status",
  })
  @ApiResponse({
    status: 200,
    description:
      'Driver profile and status retrieved.' /* type: User - define a specific Response DTO */,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - User is not a driver.',
  }) // Should be caught by role check in service/guard
  @ApiResponse({ status: 404, description: 'Not Found - Driver not found.' })
  async getDriverProfileStatus(
    @User() driver: IUser,
  ): Promise<{ message: string; data: any }> {
    // Use 'any' or create specific DTO
    this.logger.log(`Fetching profile status for driver ${driver._id}`);
    const profileData = await this.driverService.getDriverProfileAndStatus(
      driver._id,
    );
    return {
      message: 'Driver profile and status fetched successfully.',
      data: profileData, // Return the selected data
    };
  }
}
