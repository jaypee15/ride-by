import {
  ActionEnum,
  IRole,
  RoleNameEnum,
  Subject,
  UserLoginStrategy,
} from 'src/core/interfaces';

export const admins: { data: any; role: RoleNameEnum }[] = [
  {
    data: {
      email: 'superadmin@traveazi.com',
      firstName: 'Super',
      lastName: 'Admin',
      strategy: UserLoginStrategy.LOCAL,
      emailConfirm: true,
      roles: [],
    },
    role: RoleNameEnum.SuperAdmin,
  },

  {
    data: {
      email: 'admin@traveazi.com',
      firstName: 'Admin',
      lastName: 'Xtern',
      strategy: UserLoginStrategy.LOCAL,
      emailConfirm: true,
      roles: [],
    },
    role: RoleNameEnum.Admin,
  },
  {
    data: {
      email: 'support@traveazi.com',
      firstName: 'Support',
      lastName: 'Xtern',
      strategy: UserLoginStrategy.LOCAL,
      emailConfirm: true,
      roles: [],
    },
    role: RoleNameEnum.Support,
  },
];

export const roleSeed: IRole[] = [
  {
    name: RoleNameEnum.SuperAdmin,
    description: 'Super Admin',
    actions: [
      {
        action: ActionEnum.Manage,
        description: 'User management',
        subject: Subject.UserManagement,
      },
    ],
  },
  {
    name: RoleNameEnum.Admin,
    description: 'Admin',
    actions: [
      {
        action: ActionEnum.Manage,
        description: 'User management',
        subject: Subject.UserManagement,
      },
    ],
  },
  {
    name: RoleNameEnum.Support,
    description: 'Support',
    actions: [
      {
        action: ActionEnum.Read,
        description: 'User management',
        subject: Subject.UserManagement,
      },
    ],
  },
  {
    name: RoleNameEnum.Passenger,
    description: 'Passenger',
    actions: [],
  },
  {
    name: RoleNameEnum.Driver,
    description: 'Driver',
    actions: [],
  },
];
