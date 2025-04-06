import { Injectable, Logger } from '@nestjs/common';
import { S3 } from 'aws-sdk';
import { InjectAwsService } from 'nest-aws-sdk';
import { InjectAwsSecretKeys } from './decorators';
import { SecretKey } from './interfaces';

@Injectable()
export class AwsS3Service {
  private logger = new Logger(AwsS3Service.name);
  constructor(
    @InjectAwsSecretKeys() private secretKeys: SecretKey,
    @InjectAwsService(S3) private readonly s3: S3,
  ) {}

  async uploadAttachment(attachment: Express.Multer.File, fileName?: string) {
    if (!attachment) {
      return null;
    }

    fileName = fileName || this.generateFileName(attachment);
    const bucket = this.secretKeys.AWS_S3_BUCKET_NAME;

    const params = {
      Bucket: bucket,
      Key: fileName,
      Body: attachment.buffer,
      ACL: 'public-read',
    };

    const s3Response = await this.s3.upload(params).promise();

    return s3Response.Location;
  }

  private generateFileName(attachment: Express.Multer.File) {
    return `${Date.now()}-${attachment.originalname}`.replace(/\s/g, '_');
  }

  async upload(params: S3.Types.PutObjectRequest) {
    return this.s3.upload(params).promise();
  }

  async uploadToS3(fileBuffer: Buffer, fileName: string): Promise<string> {
    const bucket = this.secretKeys.AWS_S3_BUCKET_NAME;

    const params: AWS.S3.PutObjectRequest = {
      Bucket: bucket,
      Key: fileName,
      Body: fileBuffer,
      ACL: 'public-read',
    };

    const s3Response = await this.s3.upload(params).promise();
    return s3Response.Location;
  }
}
