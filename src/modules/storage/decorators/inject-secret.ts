import { Inject } from '@nestjs/common';

import { secretKeys } from '../constants';

export function InjectAwsSecretKeys() {
  return Inject(secretKeys);
}
