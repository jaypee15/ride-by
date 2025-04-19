import { Controller, Post, Body, UseGuards, Logger } from '@nestjs/common';
import { RatingService } from './rating.service';
import { SubmitRatingDto } from './dto/submit-rating.dto';
import { AuthGuard } from '../../core/guards/authenticate.guard';
import { User } from '../../core/decorators/user.decorator';
import { IUser } from '../../core/interfaces/user/user.interface';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { Rating } from './schemas/rating.schema'; // For response type hint

@ApiTags('Ratings')
@ApiBearerAuth()
@UseGuards(AuthGuard)
@Controller('ratings')
export class RatingController {
  private readonly logger = new Logger(RatingController.name);

  constructor(private readonly ratingService: RatingService) {}

  @Post()
  @ApiOperation({ summary: 'Submit a rating for a completed booking' })
  @ApiResponse({
    status: 201,
    description: 'Rating submitted successfully.',
    type: Rating,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid input or booking not completed.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - User not part of the booking.',
  })
  @ApiResponse({ status: 404, description: 'Not Found - Booking not found.' })
  @ApiResponse({
    status: 409,
    description:
      'Conflict - Rating already submitted for this booking by this user.',
  })
  async submitRating(
    @User() rater: IUser,
    @Body() submitRatingDto: SubmitRatingDto,
  ): Promise<{ message: string; data: Rating }> {
    this.logger.log(
      `User ${rater._id} submitting rating for booking ${submitRatingDto.bookingId}`,
    );
    const newRating = await this.ratingService.submitRating(
      rater._id,
      submitRatingDto,
    );
    return {
      message: 'Rating submitted successfully.',
      data: newRating.toObject() as Rating,
    };
  }
}
