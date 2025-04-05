import { DateTime, DurationLike } from 'luxon';

export class DateHelper {
  static isAfter(date: Date, dateToCompare: Date): boolean {
    return (
      DateTime.fromJSDate(new Date(date)) >
      DateTime.fromJSDate(new Date(dateToCompare))
    );
  }

  static addToCurrent(duration: DurationLike): Date {
    const dt = DateTime.now();
    return dt.plus(duration).toJSDate();
  }

  static isAfterCurrent(date: Date): boolean {
    const d1 = DateTime.fromJSDate(date ?? new Date());
    const d2 = DateTime.now();
    return d2 > d1;
  }
}
