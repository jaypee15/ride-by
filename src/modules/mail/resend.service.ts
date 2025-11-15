import { Injectable, Logger } from '@nestjs/common';
import { SecretsService } from 'src/global/secrets/service';
import { Resend } from 'resend';

export interface SendEmailPayload {
  to: string | string[];
  subject: string;
  html?: string;
  text?: string;
  headers?: Record<string, string>;
}

@Injectable()
export class ResendService {
  private readonly logger = new Logger(ResendService.name);
  private readonly resendClient: Resend | null = null;
  private readonly fromAddress: string;

  constructor(private readonly secrets: SecretsService) {
    const { RESEND_API_KEY, RESEND_FROM_EMAIL, RESEND_FROM_NAME } =
      this.secrets.resend;
    if (RESEND_API_KEY) {
      this.resendClient = new Resend(RESEND_API_KEY);
    } else {
      this.logger.error(
        'RESEND_API_KEY not configured. Email sending will not work.',
      );
    }
    this.fromAddress = RESEND_FROM_NAME
      ? `${RESEND_FROM_NAME} <${RESEND_FROM_EMAIL}>`
      : RESEND_FROM_EMAIL;
  }

  async sendEmail(payload: SendEmailPayload): Promise<void> {
    if (!this.resendClient) {
      throw new Error('Resend client not initialized');
    }
    const toArray = Array.isArray(payload.to) ? payload.to : [payload.to];
    this.logger.log(
      `Sending email via Resend to ${toArray.join(', ')} with subject "${payload.subject}"`,
    );
    const result = await this.resendClient.emails.send({
      from: this.fromAddress,
      to: toArray,
      subject: payload.subject,
      html: payload.html,
      text: payload.text,
      headers: payload.headers,
    });
    if ((result as any)?.error) {
      const error = (result as any).error;
      this.logger.error(`Resend send error: ${error?.message || error}`);
      throw new Error(error?.message || 'Failed to send email');
    }
  }
}
