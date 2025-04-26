import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RoleNameEnum } from '../interfaces/user/role.interface';
import { IUser } from '../interfaces/user/user.interface';
import { ROLES_KEY } from '../decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<RoleNameEnum[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!requiredRoles || requiredRoles.length === 0) {
      // If no roles are specified, access is allowed by default (AuthGuard already ran)
      // Or you might want to deny access if no roles specified for extra security
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user as IUser; // Assumes user object attached by AuthGuard

    if (!user || !user.roles) {
      // This shouldn't happen if AuthGuard ran successfully, but good check
      throw new ForbiddenException('User role information is missing.');
    }

    // Check if the user has at least one of the required roles
    const hasRequiredRole = requiredRoles.some(
      (role) =>
        // IMPORTANT: Check how roles are stored on your user object.
        // If user.roles is an array of Role *objects* with a 'name' property:
        (user.roles as any[]).some((userRole) => userRole.name === role),
      // If user.roles is an array of *strings* (role names):
      // user.roles.includes(role)
    );

    if (!hasRequiredRole) {
      throw new ForbiddenException(
        `Access denied. Required roles: ${requiredRoles.join(', ')}`,
      );
    }

    return true;
  }
}
