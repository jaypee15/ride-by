/* eslint-disable @typescript-eslint/no-explicit-any */
import { StatusEnum } from '.';
import { UserGender } from './role.interface';

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
  status?: StatusEnum;
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
  status?: StatusEnum;
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
  status?: StatusEnum;
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
  status?: StatusEnum;
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
  status?: StatusEnum;
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
