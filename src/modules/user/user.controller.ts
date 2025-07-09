import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
  ApiBody,
} from '@nestjs/swagger';
import {
  Patch,
  Controller,
  UseGuards,
  Logger,
  Body,
  Delete,
  Post,
} from '@nestjs/common'; // Import Patch
import { UpdateEmergencyContactsDto } from '../user/dto/emergency-contact.dto'; // Import DTO
import { UserService } from '../user/user.service'; // Import UserService
import { AuthGuard } from 'src/core/guards';
import { IUser } from 'src/core/interfaces';
import { User } from 'src/core/decorators';
import { RegisterDeviceDto } from '../user/dto/register-device.dto';

@ApiTags('User') // Modify tag if adding profile endpoints
@Controller('user')
export class UserController {
  private readonly logger = new Logger(UserController.name);
  constructor(
    private userService: UserService, // Inject UserService
  ) {}

  // ... (existing auth endpoints) ...

  @Patch('/profile/emergency-contacts') // Use PATCH for updates
  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: "Update the logged-in user's emergency contacts" })
  @ApiResponse({
    status: 200,
    description: 'Emergency contacts updated successfully.' /* type: User? */,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid input data.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({ status: 404, description: 'Not Found - User not found.' })
  async updateEmergencyContacts(
    @User() currentUser: IUser,
    @Body() updateDto: UpdateEmergencyContactsDto,
  ): Promise<{ message: string; data?: any }> {
    // Return success message
    this.logger.log(`User ${currentUser._id} updating emergency contacts.`);
    await this.userService.updateEmergencyContacts(currentUser._id, updateDto);
    return {
      message: 'Emergency contacts updated successfully.',
      // Optionally return updated contacts or user profile snippet
    };
  }

  @Post('devices/register')
  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Register a device token for push notifications' })
  @ApiResponse({ status: 200, description: 'Device registered successfully.' })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({ status: 400, description: 'Bad Request - Missing token.' })
  async registerDevice(
    @User() currentUser: IUser,
    @Body() dto: RegisterDeviceDto,
  ): Promise<{ message: string }> {
    await this.userService.addDeviceToken(currentUser._id, dto.deviceToken);
    return { message: 'Device registered successfully.' };
  }

  @Delete('devices/unregister') // Use DELETE method
  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Unregister a device token for push notifications' })
  @ApiResponse({
    status: 200,
    description: 'Device unregistered successfully.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiBody({ type: RegisterDeviceDto }) // Reuse DTO for body structure
  async unregisterDevice(
    @User() currentUser: IUser,
    @Body() dto: RegisterDeviceDto, // Get token from body
  ): Promise<{ message: string }> {
    await this.userService.removeDeviceToken(currentUser._id, dto.deviceToken);
    return { message: 'Device unregistered successfully.' };
  }
}
