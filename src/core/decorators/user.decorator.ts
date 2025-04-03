/* eslint-disable @typescript-eslint/no-explicit-any */
import { createParamDecorator, ExecutionContext } from '@nestjs/common';

import { IUser } from '../../core/interfaces';

export const User = createParamDecorator<any, any>(
  (data: string, ctx: ExecutionContext): IUser | any =>{
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;

    // eslint-disable-next-line security/detect-object-injection
    return data ? user[data] : user;
  },
);
