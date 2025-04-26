/* eslint-disable @typescript-eslint/no-explicit-any */
import { Types } from 'mongoose';
import { UserGender } from 'src/core/enums/user.enum';
import { UserStatus } from 'src/core/enums/user.enum';
import { Role } from 'src/modules/user/schemas/role.schema';

export interface IUser {
  _id: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  avatar?: string;
  about?: string;
  country?: string;
  gender?: UserGender;
  phoneNumber?: string;
  emailConfirm: boolean;
  createdAt?: Date;
  lastSeen?: Date;
  status?: UserStatus;
  roles?: Types.ObjectId[] | Role[];
}

export interface IDriver {
  _id: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  avatar?: string;
  about?: string;
  country?: string;
  gender?: UserGender;
  phoneNumber?: string;
  emailConfirm: boolean;
  createdAt?: Date;
  lastSeen?: Date;
  status?: UserStatus;
}

export interface IPassenger {
  _id: string;
  email?: string;
  firstName: string;
  lastName: string;
  avatar?: string;
  about?: string;
  country?: string;
  gender?: UserGender;
  phoneNumber?: string;
  emailConfirm?: boolean;
  createdAt?: Date;
  lastSeen?: Date;
  status?: UserStatus;
}

export interface IAdmin {
  _id?: string;
  email: string;
  firstName: string;
  lastName: string;
  avatar?: string;
  about?: string;
  country?: string;
  gender?: UserGender;
  phoneNumber?: string;
  emailConfirm: boolean;
  createdAt?: Date;
  lastSeen?: Date;
  status?: UserStatus;
}

export interface IUserMail {
  email: string;
  firstName: string;
}

export enum UserLoginStrategy {
  LOCAL = 'local',
  GOOGLE = 'google',
  FACEBOOK = 'facebook',
  APPLE = 'apple',
}
