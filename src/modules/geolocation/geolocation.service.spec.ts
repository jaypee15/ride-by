import { GeolocationService } from './geolocation.service';

describe('GeolocationService.autocomplete', () => {
  const makeService = () =>
    new GeolocationService({ googleMaps: { apiKey: 'test-key' } } as any);

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('maps predictions to description/placeId', async () => {
    jest.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      json: async () => ({
        suggestions: [
          { placePrediction: { placeId: 'ChIJ1', text: { text: 'Ikeja, Lagos, Nigeria' } } },
          { placePrediction: { placeId: 'ChIJ2', text: { text: 'Ikeja GRA, Lagos' } } },
        ],
      }),
    } as any);
    await expect(makeService().autocomplete('Ikeja')).resolves.toEqual([
      { description: 'Ikeja, Lagos, Nigeria', placeId: 'ChIJ1' },
      { description: 'Ikeja GRA, Lagos', placeId: 'ChIJ2' },
    ]);
  });

  it('returns [] when there are no suggestions', async () => {
    jest.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      json: async () => ({}),
    } as any);
    await expect(makeService().autocomplete('xqzqzq')).resolves.toEqual([]);
  });

  it('throws when the key is missing', async () => {
    const service = new GeolocationService({ googleMaps: {} } as any);
    await expect(service.autocomplete('Ikeja')).rejects.toThrow();
  });
});
