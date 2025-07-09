export enum UserGender {
  MALE = 'MALE',
  FEMALE = 'FEMALE',
}

export enum UserStatus {
  ACTIVE = 'ACTIVE', // Verified and active
  INACTIVE = 'INACTIVE', // Deactivated by user or admin
  PENDING_EMAIL_VERIFICATION = 'PENDING_EMAIL_VERIFICATION', // Registered but email not verified
  PENDING_DRIVER_VERIFICATION = 'PENDING_DRIVER_VERIFICATION', // Email verified, driver docs submitted, pending admin approval
  SUSPENDED = 'SUSPENDED', // Temporarily suspended by admin
  BANNED = 'BANNED', // Permanently banned by admin
  PENDING_PROFILE_COMPLETION = 'PENDING_PROFILE_COMPLETION', // Registered but profile not completed
}

export enum DriverVerificationStatus {
  NOT_SUBMITTED = 'NOT_SUBMITTED',
  PENDING = 'PENDING',
  VERIFIED = 'VERIFIED',
  REJECTED = 'REJECTED',
}
