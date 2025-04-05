import { BaseRegistrationDto } from 'src/modules/auth/dto/base-registeration.dto';

// For the initial user creation, driver-specific details like license and vehicle info
// are usually collected *after* the account is created during an onboarding/verification flow.
// Therefore, this DTO extends the base without additional required fields for registration itself.
export class DriverRegistrationDto extends BaseRegistrationDto {}
