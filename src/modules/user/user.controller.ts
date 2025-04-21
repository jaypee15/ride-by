import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { Patch, Controller, UseGuards, Logger, Body } from '@nestjs/common'; // Import Patch
import { UpdateEmergencyContactsDto } from '../user/dto/emergency-contact.dto'; // Import DTO
import { UserService } from '../user/user.service'; // Import UserService
import { AuthGuard } from 'src/core/guards';
import { IUser } from 'src/core/interfaces';
import { User } from 'src/core/decorators';

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
}
