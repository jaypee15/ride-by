import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsNotEmpty,
  IsPhoneNumber,
  IsString,
  MaxLength,
  ValidateNested,
} from 'class-validator';

class EmergencyContactItemDto {
  @ApiProperty({ description: "Contact's full name", example: 'Jane Doe' })
  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  name: string;

  @ApiProperty({
    description: "Contact's phone number (Nigerian format)",
    example: '+2348012345678',
  })
  @IsPhoneNumber('NG', {
    message:
      'Please provide a valid Nigerian phone number for the emergency contact.',
  })
  @IsNotEmpty()
  phone: string;
}

export class UpdateEmergencyContactsDto {
  @ApiProperty({
    description: 'List of emergency contacts (maximum 3)',
    type: [EmergencyContactItemDto], // Array of the nested DTO
    minItems: 0, // Allow empty array to clear contacts
    maxItems: 3, // Set maximum contacts
  })
  @IsArray()
  @ValidateNested({ each: true }) // Validate each item in the array
  @ArrayMinSize(0)
  @ArrayMaxSize(3, {
    message: 'You can add a maximum of 3 emergency contacts.',
  })
  @Type(() => EmergencyContactItemDto) // Important for nested validation
  contacts: EmergencyContactItemDto[];
}
