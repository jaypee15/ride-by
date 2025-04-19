import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Vehicle, VehicleDocument } from './schemas/vehicle.schema';
import { User, UserDocument } from '../user/schemas/user.schema'; // Verify path
import { RoleNameEnum } from '../../core/interfaces/user/role.interface';
import { RegisterVehicleDto } from './dto/register-vehicle.dto';
import { ErrorHelper } from 'src/core/helpers'; // Use ErrorHelper for consistency
import { AwsS3Service } from '../storage/s3-bucket.service'; // Import S3 Service
import { VehicleDocumentType } from './enums/vehicle-document-type.enum';
import { VehicleVerificationStatus } from 'src/core/enums/vehicle.enum';

@Injectable()
export class DriverService {
  private readonly logger = new Logger(DriverService.name);

  constructor(
    @InjectModel(Vehicle.name) private vehicleModel: Model<VehicleDocument>,
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private readonly awsS3Service: AwsS3Service,
  ) {}

  async registerVehicle(
    driverId: string,
    dto: RegisterVehicleDto,
  ): Promise<VehicleDocument> {
    this.logger.log(
      `Attempting to register vehicle for driver ID: ${driverId}`,
    );

    // 1. Verify User is a Driver
    const driver = await this.userModel.findById(driverId).populate('roles');
    if (!driver) {
      this.logger.warn(`Driver not found for ID: ${driverId}`);
      ErrorHelper.NotFoundException('Driver user not found.');
    }
    const isDriverRole = driver.roles.some(
      (role) => role.name === RoleNameEnum.Driver,
    );
    if (!isDriverRole) {
      this.logger.warn(`User ${driverId} does not have DRIVER role.`);
      ErrorHelper.ForbiddenException('User is not registered as a driver.');
    }

    // 2. Check for duplicate plate number (case-insensitive suggested)
    const plateUpper = dto.plateNumber.toUpperCase();
    const existingVehicle = await this.vehicleModel.findOne({
      plateNumber: plateUpper,
    });
    if (existingVehicle) {
      this.logger.warn(
        `Vehicle with plate number ${plateUpper} already exists.`,
      );
      ErrorHelper.ConflictException(
        `Vehicle with plate number ${dto.plateNumber} already exists.`,
      );
    }

    // 3. Create and Save Vehicle
    try {
      const newVehicle = new this.vehicleModel({
        ...dto,
        plateNumber: plateUpper, // Store uppercase
        driver: driverId, // Link to the driver user
        // vehicleVerificationStatus defaults to NOT_SUBMITTED via schema
      });
      await newVehicle.save();
      this.logger.log(
        `Vehicle ${newVehicle._id} created successfully for driver ${driverId}.`,
      );

      // 4. Update User's vehicles array
      await this.userModel.findByIdAndUpdate(driverId, {
        $push: { vehicles: newVehicle._id },
      });
      this.logger.log(`Updated driver ${driverId}'s vehicle list.`);

      return newVehicle; // Return the saved document
    } catch (error) {
      this.logger.error(
        `Error registering vehicle for driver ${driverId}: ${error.message}`,
        error.stack,
      );
      if (error.code === 11000) {
        // Handle potential race condition for unique index
        ErrorHelper.ConflictException(
          `Vehicle with plate number ${dto.plateNumber} already exists.`,
        );
      }
      ErrorHelper.InternalServerErrorException('Failed to register vehicle.');
    }
  }

  async uploadVehicleDocument(
    driverId: string,
    vehicleId: string,
    file: Express.Multer.File,
    documentType: VehicleDocumentType,
  ): Promise<VehicleDocument> {
    this.logger.log(
      `Attempting to upload document type ${documentType} for vehicle ${vehicleId} by driver ${driverId}`,
    );

    if (!file) {
      ErrorHelper.BadRequestException('Document file is required.');
    }

    // 1. Find vehicle and verify ownership
    const vehicle = await this.vehicleModel.findById(vehicleId);
    if (!vehicle) {
      ErrorHelper.NotFoundException(`Vehicle with ID ${vehicleId} not found.`);
    }
    // Ensure the driver owns this vehicle - Use .toString() for ObjectId comparison
    if (vehicle.driver.toString() !== driverId) {
      this.logger.warn(
        `Driver ${driverId} attempted to upload document for vehicle ${vehicleId} they don't own.`,
      );
      ErrorHelper.ForbiddenException(
        'You are not authorized to modify this vehicle.',
      );
    }

    // 2. Upload to S3
    let fileUrl: string;
    try {
      // Define a structured key/filename for S3
      const s3FileName = `vehicle-documents/${driverId}/${vehicleId}/${documentType}-${Date.now()}-${file.originalname}`;
      fileUrl = await this.awsS3Service.uploadAttachment(file, s3FileName);
      this.logger.log(`Document uploaded to S3: ${fileUrl}`);
    } catch (error) {
      this.logger.error(
        `Failed to upload vehicle document to S3: ${error.message}`,
        error.stack,
      );
      ErrorHelper.InternalServerErrorException('Failed to upload document.');
    }

    // 3. Determine which field to update
    let updateField: string;
    switch (documentType) {
      case VehicleDocumentType.REGISTRATION:
        updateField = 'vehicleRegistrationImageUrl';
        break;
      case VehicleDocumentType.INSURANCE:
        updateField = 'vehicleInsuranceImageUrl';
        break;
      case VehicleDocumentType.PROOF_OF_OWNERSHIP:
        updateField = 'proofOfOwnershipImageUrl';
        break;
      case VehicleDocumentType.ROADWORTHINESS:
        updateField = 'roadworthinessImageUrl';
        break;
      // Add cases for other document types if needed
      default:
        this.logger.error(`Invalid document type provided: ${documentType}`);
        ErrorHelper.BadRequestException('Invalid document type specified.');
    }

    // 4. Update Vehicle Document in DB
    try {
      // Update the specific field and potentially the status if it wasn't already PENDING or VERIFIED
      const updateData: Partial<Vehicle> = { [updateField]: fileUrl };
      if (
        vehicle.vehicleVerificationStatus ===
          VehicleVerificationStatus.NOT_SUBMITTED ||
        vehicle.vehicleVerificationStatus === VehicleVerificationStatus.REJECTED
      ) {
        // Optionally set to PENDING automatically on first upload or re-upload after rejection
        // updateData.vehicleVerificationStatus = VehicleVerificationStatus.PENDING;
        // More robust logic might check if ALL required docs are present before setting PENDING.
        // For now, just upload the URL. Verification status change can be manual via admin or a separate trigger.
      }

      const updatedVehicle = await this.vehicleModel.findByIdAndUpdate(
        vehicleId,
        { $set: updateData },
        { new: true }, // Return the updated document
      );

      if (!updatedVehicle) {
        // Should not happen if findById worked, but good practice
        ErrorHelper.NotFoundException(
          `Vehicle with ID ${vehicleId} disappeared during update.`,
        );
      }

      this.logger.log(
        `Updated vehicle ${vehicleId} with document URL for type ${documentType}.`,
      );
      return updatedVehicle;
    } catch (error) {
      this.logger.error(
        `Failed to update vehicle ${vehicleId} in DB after S3 upload: ${error.message}`,
        error.stack,
      );
      // Consider attempting to delete the uploaded S3 file on DB update failure (compensation logic)
      ErrorHelper.InternalServerErrorException(
        'Failed to save document information.',
      );
    }
  }
}
