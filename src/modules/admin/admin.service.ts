import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from '../user/schemas/user.schema';
import { Vehicle, VehicleDocument } from '../driver/schemas/vehicle.schema';
import { DriverVerificationStatus, UserStatus } from 'src/core/enums/user.enum';
import { VehicleVerificationStatus } from 'src/core/enums/vehicle.enum';
import {
  UpdateDriverVerificationDto,
  UpdateVehicleVerificationDto,
} from './dto/update-verification.dto';
import { ErrorHelper } from 'src/core/helpers';

@Injectable()
export class AdminService {
  private readonly logger = new Logger(AdminService.name);

  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    @InjectModel(Vehicle.name) private vehicleModel: Model<VehicleDocument>,
    // TODO: Inject NotificationService later
  ) {}

  // --- Get Pending Verifications ---

  async getPendingDriverVerifications(): Promise<UserDocument[]> {
    this.logger.log('Fetching pending driver verifications');
    // Find users who have the DRIVER role and status PENDING_DRIVER_VERIFICATION
    // Adjust query based on your exact status flow for document submission
    return this.userModel
      .find({
        // 'roles.name': RoleNameEnum.Driver, // This requires querying populated roles or storing role name directly
        driverVerificationStatus: DriverVerificationStatus.PENDING, // Assuming status is set to PENDING when docs are uploaded
      })
      .select(
        'firstName lastName email driverLicenseFrontImageUrl driverLicenseBackImageUrl createdAt',
      ) // Select relevant fields
      .exec();
  }

  async getPendingVehicleVerifications(): Promise<VehicleDocument[]> {
    this.logger.log('Fetching pending vehicle verifications');
    return this.vehicleModel
      .find({
        vehicleVerificationStatus: VehicleVerificationStatus.PENDING,
      })
      .populate<{ driver: UserDocument }>('driver', 'firstName lastName email') // Show driver info
      .select(
        'make model year plateNumber vehicleRegistrationImageUrl vehicleInsuranceImageUrl proofOfOwnershipImageUrl createdAt',
      ) // Select relevant fields
      .exec();
  }

  // --- Update Verification Statuses ---

  async updateDriverVerificationStatus(
    adminUserId: string,
    targetUserId: string,
    dto: UpdateDriverVerificationDto,
  ): Promise<UserDocument> {
    this.logger.log(
      `Admin ${adminUserId} updating verification status for driver ${targetUserId} to ${dto.status}`,
    );

    const driver = await this.userModel.findById(targetUserId);
    if (!driver) {
      ErrorHelper.NotFoundException(`User with ID ${targetUserId} not found.`);
    }
    // Add check: ensure target user actually IS a driver?

    // Allow update only if current status is PENDING (or maybe REJECTED for re-verification)
    const validPreviousStatuses = [
      DriverVerificationStatus.PENDING,
      DriverVerificationStatus.REJECTED,
    ];
    if (!validPreviousStatuses.includes(driver.driverVerificationStatus)) {
      ErrorHelper.BadRequestException(
        `Cannot update verification status from current state: ${driver.driverVerificationStatus}`,
      );
    }

    driver.driverVerificationStatus = dto.status;
    driver.driverRejectionReason =
      dto.status === DriverVerificationStatus.REJECTED ? dto.reason : undefined;

    // IMPORTANT: Update User's overall status if they are now fully verified
    if (
      dto.status === DriverVerificationStatus.VERIFIED &&
      driver.status === UserStatus.PENDING_DRIVER_VERIFICATION
    ) {
      driver.status = UserStatus.ACTIVE;
      this.logger.log(`Setting user ${targetUserId} status to ACTIVE.`);
    } else if (dto.status === DriverVerificationStatus.REJECTED) {
      // Optional: Change user status back if needed, e.g., to PENDING_DRIVER_VERIFICATION or keep as ACTIVE but rejected
      // driver.status = UserStatus.PENDING_DRIVER_VERIFICATION;
    }

    await driver.save();

    // TODO: Send notification to driver about status change (Phase 6)
    // await this.notificationService.notifyDriverVerificationUpdate(driver, dto.status, dto.reason);

    this.logger.log(
      `Successfully updated driver ${targetUserId} verification status to ${dto.status}`,
    );
    return driver;
  }

  async updateVehicleVerificationStatus(
    adminUserId: string,
    vehicleId: string,
    dto: UpdateVehicleVerificationDto,
  ): Promise<VehicleDocument> {
    this.logger.log(
      `Admin ${adminUserId} updating verification status for vehicle ${vehicleId} to ${dto.status}`,
    );

    const vehicle = await this.vehicleModel.findById(vehicleId);
    if (!vehicle) {
      ErrorHelper.NotFoundException(`Vehicle with ID ${vehicleId} not found.`);
    }

    const validPreviousStatuses = [
      VehicleVerificationStatus.PENDING,
      VehicleVerificationStatus.REJECTED,
    ];
    if (!validPreviousStatuses.includes(vehicle.vehicleVerificationStatus)) {
      ErrorHelper.BadRequestException(
        `Cannot update verification status from current state: ${vehicle.vehicleVerificationStatus}`,
      );
    }

    vehicle.vehicleVerificationStatus = dto.status;
    vehicle.vehicleRejectionReason =
      dto.status === VehicleVerificationStatus.REJECTED
        ? dto.reason
        : undefined;

    await vehicle.save();

    // TODO: Send notification to driver about status change (Phase 6)
    // await this.notificationService.notifyVehicleVerificationUpdate(vehicle.driver, vehicle, dto.status, dto.reason);

    this.logger.log(
      `Successfully updated vehicle ${vehicleId} verification status to ${dto.status}`,
    );
    return vehicle;
  }
}
