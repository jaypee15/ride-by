import { BaseRegistrationDto } from 'src/modules/auth/dto/base-registeration.dto';

// Currently, no additional fields are strictly required for passenger *initial* registration
// beyond the base fields. Specific preferences might be added later during onboarding.
export class PassengerRegistrationDto extends BaseRegistrationDto {}
