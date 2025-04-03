import { validate, ValidationError } from 'class-validator';

type Class = { new (...args: unknown[]): unknown };

const getMessages = (error: ValidationError) => {
  return Object.values(error.constraints).join(', ');
};

const validateDto = async (dto: Class, data: object) => {
  const d = Object.assign(new dto(), data);

  const errors = await validate(d);

  if (errors.length === 0) return null;

  return errors.map(getMessages).join('\n');
};

export default validateDto;
