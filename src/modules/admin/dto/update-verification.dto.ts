import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsEnum,
  IsNotEmpty,
  IsOptional,
  IsString,
  ValidateIf,
} from 'class-validator';
import { DriverVerificationStatus } from 'src/core/enums/user.enum';
import { VehicleVerificationStatus } from 'src/core/enums/vehicle.enum';

export class UpdateDriverVerificationDto {
  @ApiProperty({
    enum: [
      DriverVerificationStatus.VERIFIED,
      DriverVerificationStatus.REJECTED,
    ],
    description: 'New status for driver verification',
  })
  @IsEnum([
    DriverVerificationStatus.VERIFIED,
    DriverVerificationStatus.REJECTED,
  ]) // Admin can only Verify or Reject
  @IsNotEmpty()
  status: DriverVerificationStatus.VERIFIED | DriverVerificationStatus.REJECTED;

  @ApiPropertyOptional({
    description: 'Reason for rejection (required if status is REJECTED)',
  })
  @IsOptional()
  @ValidateIf((o) => o.status === DriverVerificationStatus.REJECTED) // Require reason only if rejecting
  @IsNotEmpty({ message: 'Rejection reason is required when rejecting.' })
  @IsString()
  reason?: string;
}

export class UpdateVehicleVerificationDto {
  @ApiProperty({
    enum: [
      VehicleVerificationStatus.VERIFIED,
      VehicleVerificationStatus.REJECTED,
    ],
    description: 'New status for vehicle verification',
  })
  @IsEnum([
    VehicleVerificationStatus.VERIFIED,
    VehicleVerificationStatus.REJECTED,
  ])
  @IsNotEmpty()
  status:
    | VehicleVerificationStatus.VERIFIED
    | VehicleVerificationStatus.REJECTED;

  @ApiPropertyOptional({
    description: 'Reason for rejection (required if status is REJECTED)',
  })
  @IsOptional()
  @ValidateIf((o) => o.status === VehicleVerificationStatus.REJECTED)
  @IsNotEmpty({ message: 'Rejection reason is required when rejecting.' })
  @IsString()
  reason?: string;
}
