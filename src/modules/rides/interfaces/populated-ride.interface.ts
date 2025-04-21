import { BookingDocument } from '../../booking/schemas/booking.schema';
import { RideDocument } from '../schemas/ride.schema';

export interface PopulatedRideWithBookings
  extends Omit<RideDocument, 'bookings'> {
  bookings: BookingDocument[];
}
