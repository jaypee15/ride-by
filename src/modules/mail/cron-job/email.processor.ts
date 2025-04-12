import { Processor, Process } from '@nestjs/bull';
import { Job } from 'bull';
import { Injectable, Logger } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import * as ejs from 'ejs';
import * as fs from 'fs';
import * as path from 'path';

@Processor('emailQueue')
@Injectable()
export class EmailProcessor {
  private logger = new Logger(EmailProcessor.name);

  constructor(private mailerService: MailerService) {}

  private from = '"TravEazi Team" <notifications@travezi.com>';

  // Resolve the path and read the template file
  private marketingTemplatePath = path.resolve(
    __dirname,
    '..',
    'templates',
    'marketing.ejs',
  );

  private marketingEmailTemplate = fs.readFileSync(this.marketingTemplatePath, {
    encoding: 'utf-8',
  });

  @Process('sendBulkEmail')
  async handleBulkEmailJob(job: Job) {
    const data = job.data;
    const batchSize = 50; // Number of emails per batch
    const maxRetries = 3; // Maximum number of retries
    const batches = [];

    for (let i = 0; i < data.to.length; i += batchSize) {
      batches.push(data.to.slice(i, i + batchSize));
    }

    this.logger.log(`Scheduled time for job ${job.id}: ${data.sendTime}`);

    for (const batch of batches) {
      const emailPromises = batch.map((recipient) => {
        let retries = 0;
        const sendEmail = async () => {
          try {
            return await this.mailerService.sendMail({
              to: recipient.email,
              from: this.from,
              subject: data.subject,
              context: {
                name: recipient.firstName,
                email: data.email,
                body: data.body,
              },
              headers: {
                'X-Category': data.type,
              },
              html: ejs.render(this.marketingEmailTemplate, {
                subject: data.subject,
                name: recipient.firstName,
                body: data.body,
              }),
              text: ejs.render(this.marketingEmailTemplate, {
                subject: data.subject,
                name: recipient.firstName,
                body: data.body,
              }),
            });
          } catch (error) {
            if (retries < maxRetries) {
              retries++;
              this.logger.warn(
                `Retry ${retries} for email to ${recipient.email}`,
              );
              await new Promise((resolve) => setTimeout(resolve, 1000)); // Wait for 1 second before retrying
              return sendEmail();
            } else {
              throw error;
            }
          }
        };
        return sendEmail();
      });

      try {
        const results = await Promise.all(emailPromises);
        this.logger.log(`Batch sent successfully: ${results}`);
      } catch (error) {
        this.logger.error(`Failed to send batch: ${error.message}`);
        throw error;
      }

      await new Promise((resolve) => setTimeout(resolve, 1000)); // Wait for 1 second before sending the next batch
    }

    await job.update({ status: 'completed' });
    return { status: 'completed', jobId: job.id };
  }
}
