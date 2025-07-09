import {
  Controller,
  Post,
  Req,
  RawBodyRequest,
  Headers,
  Logger,
  HttpStatus,
  HttpCode,
} from '@nestjs/common';
import { Request } from 'express';
import { PaymentService } from './payment.service';
import { ApiTags, ApiOperation, ApiResponse, ApiHeader } from '@nestjs/swagger';
import { ErrorHelper } from 'src/core/helpers';

@ApiTags('Webhooks')
@Controller('webhooks')
export class WebhookController {
  private readonly logger = new Logger(WebhookController.name);

  constructor(private readonly paymentService: PaymentService) {}

  @Post('paystack')
  @HttpCode(HttpStatus.OK) // Paystack expects 200 OK on success
  @ApiOperation({ summary: 'Handle Paystack webhook events' })
  @ApiHeader({
    name: 'x-paystack-signature',
    description: 'Paystack webhook signature',
    required: true,
  })
  @ApiResponse({
    status: 200,
    description: 'Webhook received and processing acknowledged.',
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid payload or signature.',
  })
  @ApiResponse({ status: 403, description: 'Forbidden - Invalid signature.' })
  async handlePaystackWebhook(
    @Headers('x-paystack-signature') signature: string,
    @Req() req: RawBodyRequest<Request>, // Use RawBodyRequest to get raw body buffer
  ): Promise<{ received: boolean }> {
    // IMPORTANT: Ensure express.raw({ type: 'application/json' }) middleware is applied in main.ts
    // for routes including '/webhook' to get the raw body.
    if (!req.rawBody) {
      this.logger.error(
        'Raw body not available for webhook verification. Ensure raw body middleware is configured.',
      );
      ErrorHelper.BadRequestException('Webhook configuration error.');
    }

    const rawBodyString = req.rawBody.toString();
    this.logger.log(
      `Received Paystack webhook. Signature: ${signature ? 'Present' : 'Missing'}`,
    );

    // 1. Verify Signature
    const isValid = this.paymentService.verifyWebhookSignature(
      signature,
      rawBodyString,
    );
    if (!isValid) {
      this.logger.error('Invalid Paystack webhook signature received.');
      ErrorHelper.ForbiddenException('Invalid webhook signature.'); // Use 403 for security failures
    }

    this.logger.log('Paystack webhook signature verified.');

    // 2. Parse Payload (already parsed by default if JSON, but use rawBodyString if needed)
    const payload = req.body; // Assuming express.json() ran AFTER express.raw()

    // 3. Process Event Asynchronously (Recommended for resilience)
    // You could push this to a Bull queue instead of processing directly
    try {
      await this.paymentService.handleWebhook(payload);
    } catch (error) {
      // Log the error, but still return 200 OK to Paystack to prevent retries for processing errors
      // unless it's an error you want Paystack to retry (like temporary DB issue)
      this.logger.error(
        `Error processing Paystack webhook payload: ${error.message}`,
        error.stack,
      );
      // Potentially throw specific errors if needed, but generally acknowledge receipt
      // ErroHelper.InternalServerErrorException('Webhook processing failed.');
    }

    // 4. Acknowledge Receipt to Paystack
    // Return 200 OK immediately even if background processing is ongoing
    return { received: true };
  }
}
