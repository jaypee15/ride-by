import { SetMetadata } from '@nestjs/common';
import { RoleNameEnum } from '../interfaces/user/role.interface';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: RoleNameEnum[]) =>
  SetMetadata(ROLES_KEY, roles);
