import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
} from '@nestjs/common';

import { ErrorHelper } from '../../core/helpers';
import { IUser, RequestHeadersEnum } from '../../core/interfaces'; // Ensure IUser is general enough or use a more specific type for decoded token
import { TokenHelper } from '../../global/utils/token.utils';
import { UserSessionService } from '../../global/user-session/service';

// Define a more specific type for what the token might contain
type DecodedTokenPayload = IUser & {
  sessionId?: string;
  isPartialToken?: boolean;
};

@Injectable()
export class AuthGuard implements CanActivate {
  private logger = new Logger(AuthGuard.name);

  constructor(
    private tokenHelper: TokenHelper,
    private userSession: UserSessionService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();

    const authorization =
      req.headers[RequestHeadersEnum.Authorization] ||
      String(req.cookies.accessToken);

    if (!authorization) {
      ErrorHelper.ForbiddenException('Authorization header is required');
    }

    const user = await this.verifyAccessToken(authorization);

    req.user = user; // Attach the decoded payload (either partial or full)

    return true;
  }

  async verifyAccessToken(authorization: string): Promise<DecodedTokenPayload> {
    // Return type updated
    const [bearer, accessToken] = authorization.split(' ');

    if (bearer == 'Bearer' && accessToken !== '') {
      const decodedPayload = this.tokenHelper.verify<DecodedTokenPayload>( // Verify and get payload
        accessToken,
      );

      // If it's a partial token, bypass session checks
      if (decodedPayload.isPartialToken) {
        this.logger.log(
          `Partial token verified for user ${decodedPayload._id}. Bypassing session check.`,
        );
        // Ensure the partial token contains necessary fields like _id
        if (!decodedPayload._id) {
          this.logger.error('Partial token is missing _id field.');
          ErrorHelper.UnauthorizedException('Invalid partial token.');
        }
        return decodedPayload; // Return the decoded partial payload
      }

      // --- For FULL tokens, proceed with session validation ---
      if (!decodedPayload.sessionId) {
        this.logger.error(
          `Full token is missing sessionId for user ${decodedPayload._id}`,
        );
        ErrorHelper.UnauthorizedException('Invalid token: Session ID missing.');
      }

      const session = await this.userSession.get(decodedPayload._id);

      if (!session) {
        this.logger.error(
          `verifyAccessToken: Session not found for full token ${decodedPayload._id}`,
        );
        ErrorHelper.UnauthorizedException(
          'Unauthorized! Session expired or not found.',
        );
      }

      if (session.sessionId !== decodedPayload.sessionId) {
        this.logger.error(
          `verifyAccessToken: SessionId mismatch for full token. DB: ${session.sessionId}, Token: ${decodedPayload.sessionId}`,
        );
        ErrorHelper.UnauthorizedException('Unauthorized! Session mismatch.');
      }

      return decodedPayload; // Return the decoded full user payload
    } else {
      this.logger.error(
        `verifyAccessToken: Invalid token format: ${accessToken}`,
      );
      ErrorHelper.UnauthorizedException('Unauthorized! Invalid token format.');
    }
  }
}
