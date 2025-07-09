import {
  Controller,
  Get,
  Patch,
  Param,
  Body,
  UseGuards,
  Logger,
} from '@nestjs/common';
import { AdminService } from './admin.service';
import { AuthGuard } from '../../core/guards/authenticate.guard'; // Standard AuthGuard
// import { RolesGuard } from '../../core/guards/roles.guard'; // Need a RolesGuard
// import { Roles } from '../../core/decorators/roles.decorator'; // Need a Roles decorator
import { User as CurrentUser } from '../../core/decorators/user.decorator'; // Decorator to get current user
import { IUser } from 'src/core/interfaces';
import {
  UpdateDriverVerificationDto,
  UpdateVehicleVerificationDto,
} from './dto/update-verification.dto';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiParam,
} from '@nestjs/swagger';
import { User } from '../user/schemas/user.schema'; // Import schemas for response types
import { Vehicle } from '../driver/schemas/vehicle.schema';
import mongoose from 'mongoose';
import { ErrorHelper } from 'src/core/helpers';

@ApiTags('Admin - Verifications')
@ApiBearerAuth()
// @Roles(RoleNameEnum.Admin) // Apply Roles decorator when RolesGuard is implemented
@UseGuards(AuthGuard) // Use AuthGuard first, then RolesGuard
@Controller('admin/verifications')
export class AdminController {
  private readonly logger = new Logger(AdminController.name);

  constructor(private readonly adminService: AdminService) {}

  @Get('drivers/pending')
  @ApiOperation({
    summary: 'Get list of drivers pending verification (Admin only)',
  })
  @ApiResponse({
    status: 200,
    description: 'List of pending driver verifications.',
    type: [User],
  }) // Type hint
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - User is not an Admin.',
  })
  async getPendingDrivers(): Promise<{ message: string; data: User[] }> {
    this.logger.log('Request received for pending driver verifications');
    const drivers = await this.adminService.getPendingDriverVerifications();
    return {
      message: 'Pending driver verifications fetched successfully.',
      data: drivers.map((d) => d.toObject() as User),
    };
  }

  @Get('vehicles/pending')
  @ApiOperation({
    summary: 'Get list of vehicles pending verification (Admin only)',
  })
  @ApiResponse({
    status: 200,
    description: 'List of pending vehicle verifications.',
    type: [Vehicle],
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - User is not an Admin.',
  })
  async getPendingVehicles(): Promise<{ message: string; data: Vehicle[] }> {
    this.logger.log('Request received for pending vehicle verifications');
    const vehicles = await this.adminService.getPendingVehicleVerifications();
    return {
      message: 'Pending vehicle verifications fetched successfully.',
      data: vehicles.map((v) => v.toObject() as Vehicle),
    };
  }

  @Patch('drivers/:userId/status')
  @ApiOperation({ summary: 'Update driver verification status (Admin only)' })
  @ApiParam({ name: 'userId', description: 'ID of the driver user to update' })
  @ApiResponse({
    status: 200,
    description: 'Driver verification status updated.',
    type: User,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid input or status transition.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - User is not an Admin.',
  })
  @ApiResponse({ status: 404, description: 'Not Found - User not found.' })
  async updateDriverStatus(
    @CurrentUser() admin: IUser,
    @Param('userId') userId: string,
    @Body() updateDto: UpdateDriverVerificationDto,
  ): Promise<{ message: string; data: User }> {
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      ErrorHelper.BadRequestException('Invalid User ID format.');
    }
    this.logger.log(`Admin ${admin._id} updating driver ${userId} status`);
    const updatedDriver =
      await this.adminService.updateDriverVerificationStatus(
        admin._id,
        userId,
        updateDto,
      );
    return {
      message: 'Driver verification status updated successfully.',
      data: updatedDriver.toObject() as User,
    };
  }

  @Patch('vehicles/:vehicleId/status')
  @ApiOperation({ summary: 'Update vehicle verification status (Admin only)' })
  @ApiParam({ name: 'vehicleId', description: 'ID of the vehicle to update' })
  @ApiResponse({
    status: 200,
    description: 'Vehicle verification status updated.',
    type: Vehicle,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid input or status transition.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - User is not an Admin.',
  })
  @ApiResponse({ status: 404, description: 'Not Found - Vehicle not found.' })
  async updateVehicleStatus(
    @CurrentUser() admin: IUser,
    @Param('vehicleId') vehicleId: string,
    @Body() updateDto: UpdateVehicleVerificationDto,
  ): Promise<{ message: string; data: Vehicle }> {
    if (!mongoose.Types.ObjectId.isValid(vehicleId)) {
      ErrorHelper.BadRequestException('Invalid Vehicle ID format.');
    }
    this.logger.log(`Admin ${admin._id} updating vehicle ${vehicleId} status`);
    const updatedVehicle =
      await this.adminService.updateVehicleVerificationStatus(
        admin._id,
        vehicleId,
        updateDto,
      );
    return {
      message: 'Vehicle verification status updated successfully.',
      data: updatedVehicle.toObject() as Vehicle,
    };
  }
}
