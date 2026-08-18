/**
 * The query body is validated by `RetrieverService.retrieve` itself (Effect
 * Schema → `RetrieveQueryParseError`); the route only checks the body is JSON.
 */
export const retrieveJsonError = {
  code: 'INVALID_RETRIEVE_INPUT',
  message: 'Retrieve query contains invalid or unsupported fields.'
} as const;
