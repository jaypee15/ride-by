export enum RoleNameEnum {
    Admin = 'ADMIN',
    Driver = 'DRIVER',
    Passenger = 'PASSENGER',
  }
  
  export enum ActionEnum {
    Manage = 'manage',
    Create = 'create',
    Read = 'read',
    Update = 'update',
    Delete = 'delete',
  }
  
  export enum Subject {
    UserManagement = 'USER_MANAGEMENT',
    RideManagement = 'RIDE_MANAGEMENT',
  }
  
  export interface IAction {
    action: ActionEnum;
    subject: Subject;
    description: string;
  }
  
  export interface IRole {
    name: RoleNameEnum;
    description: string;
    actions: IAction[];
  }
  
  export enum UserGender {
    MALE = 'MALE',
    FEMALE = 'FEMALE',
    OTHERS = 'OTHERS',
  }
  