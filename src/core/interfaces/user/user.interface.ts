/* eslint-disable @typescript-eslint/no-explicit-any */
import { UserGender } from 'src/core/enums/user.enum';
import { UserStatus } from 'src/core/enums/user.enum';

export interface IUser {
  _id?: string;
  firstName: string;
  lastName: string;
  email: string;
  reasonToJoin?: string;
  profession?: string;
  pathway?: string;
  techStacks?: object;
  assessmentScore?: string;
  emailConfirm: boolean;
  createdAt?: Date;
  lastSeen?: Date;
  status?: UserStatus;
}

export interface IUser {
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

export interface IDriver {
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

export interface IPassenger {
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
