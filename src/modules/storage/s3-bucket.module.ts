import { Provider } from '@nestjs/common';
import { S3 } from 'aws-sdk';
import { AwsSdkModule } from 'nest-aws-sdk';
import { AwsS3Service } from './s3-bucket.service';
import { secretKeys as secretKeysToken } from './constants';
import { SecretKey } from './interfaces';
import { SecretsService } from 'src/global/secrets/service';

export class AwsS3Module {
  static forRoot(secretKey: keyof SecretsService) {
    const AwsS3SecretKeysProvider: Provider<SecretKey> = {
      provide: secretKeysToken,
      inject: [SecretsService],
      useFactory: (secretsService: SecretsService) => secretsService[secretKey],
    };

    return {
      module: AwsS3Module,
      imports: [
        AwsSdkModule.forFeatures([S3]),
        AwsSdkModule.forRootAsync({
          defaultServiceOptions: {
            useFactory: (secretsService: SecretsService) => {
              return {
                region: secretsService[secretKey].AWS_REGION,
                credentials: {
                  accessKeyId: secretsService[secretKey].AWS_ACCESS_KEY_ID,
                  secretAccessKey:
                    secretsService[secretKey].AWS_SECRET_ACCESS_KEY,
                },
                signatureVersion: 'v4',
              };
            },
            inject: [SecretsService],
          },
        }),
      ],
      providers: [AwsS3Service, AwsS3SecretKeysProvider],
      exports: [AwsS3Service],
    };
  }
}
